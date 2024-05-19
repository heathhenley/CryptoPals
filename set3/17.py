# Set 3, Challenge 17: The CBC padding oracle
import base64
import os
import random

from Crypto.Cipher import AES

# random base64-encoded strings from the problem statement
random_strings = [
  "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]


def pad_to_modn_bytes(s, n):
  if len(s) % n == 0:
    return s + bytes([n] * n)
  pad_bytes = n - (len(s) %  n)
  return s + bytes([pad_bytes] * pad_bytes)


def remove_padding(text: bytes, block_size: int = 16):
  """ Remove padding from bytes - raise ValueError if padding is invalid """
  # get the last byte
  last_byte = text[-1]
  # check if the last byte is the padding byte
  if last_byte > block_size:
    raise ValueError("Invalid padding")
  # check if the last n bytes are the same
  if text[-last_byte:] != bytes([last_byte] * last_byte):
    raise ValueError("Invalid padding")
  return text[:-last_byte]


def repeating_xor(bstr: bytes, key: bytes):
  return bytes([b ^ key[i % len(key)]
                for i, b in enumerate(bstr)])


def encrypt_ecb(plaintext, key):
  return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def decrypt_ecb(cipher, key):
  return AES.new(key, AES.MODE_ECB).decrypt(cipher)


def encrypt_cbc(plaintext, key, iv):
  """ From previous challenge (10)"""
  if len(iv) != len(key):
    raise ValueError("IV must be same length as key")

  plaintext = pad_to_modn_bytes(plaintext, len(key))

  block_size  = len(key)
  ciphertext = b""
  for block_idx in range(0, len(plaintext) // block_size):
    start = block_idx*block_size
    end = start + block_size
    block = plaintext[start:end]
    # xor plaintext block with previous ciphertext block
    if block_idx == 0:
      block = repeating_xor(block, iv)
    else:
      block = repeating_xor(block, ciphertext[start-block_size:start])
    # encrypt using ECB
    ciphertext += encrypt_ecb(block, key)
  return ciphertext


def decrypt_cbc(ciphertext, key, iv):

  if len(iv) != len(key):
    raise ValueError("IV must be same length as key")

  if len(ciphertext) % len(key) != 0:
    raise ValueError("Ciphertext must be multiple of key length")
  
  block_size = len(key)
  plaintext = b""
  for block_idx in range(0, len(ciphertext) // block_size):
    start = block_idx*block_size
    end = start + block_size
    block = ciphertext[start:end]
    # decrypt using ECB
    block = decrypt_ecb(block, key)
    # xor with previous ciphertext block
    if block_idx == 0:
      block = repeating_xor(block, iv)
    else:
      block = repeating_xor(block, ciphertext[start-block_size:start])
    plaintext += block
  return plaintext


def get_padding_oracle(key):
  def decrypt_and_check_padding(ciphertext: bytes, iv: bytes):
    """ Decrypt ciphertext, and check padding """
    plaintext = decrypt_cbc(ciphertext, key, iv)
    try:
      remove_padding(plaintext)
      return True
    except ValueError:
      return False
  return decrypt_and_check_padding


def bytes_xor(b1: bytes, b2: bytes) -> bytes:
  return bytes([a ^ b for a, b in zip(b1, b2)])


def single_block_attack(block, oracle):
  """Returns the decryption of the given ciphertext block.

  This is from:
  https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
  Because I got stuck on this one... it actually turned out that
  I was not doing anything wrong in this part, but function to remove padding
  and raise if was not valid was wrong. :(

  """

  # zeroing_iv starts out nulled. each iteration of the main loop will add
  # one byte to it, working from right to left, until it is fully populated,
  # at which point it contains the result of DEC(ct_block)
  block_size = len(block)
  zeroing_iv = [0] * block_size
  for pad_val in range(1, block_size+1):
    padding_iv = [pad_val ^ b for b in zeroing_iv]
    for candidate in range(256):
      padding_iv[-pad_val] = candidate
      iv = bytes(padding_iv)
      if oracle(block, iv):
        if pad_val == 1:
          # make sure the padding really is of length 1 by changing
          # the penultimate block and querying the oracle again
          padding_iv[-2] ^= 1
          iv = bytes(padding_iv)
          if not oracle(block, iv):
            continue  # false positive; keep searching
        break
    else:
      raise Exception("no valid padding byte found") 
    zeroing_iv[-pad_val] = candidate ^ pad_val
  return zeroing_iv


def crack_cbc(iv: bytes, ciphertext: bytes, padding_oracle: callable):
  """ Crack CBC using padding oracle """
  # all the oracle will do is check if the padding is valid or not
  # we have to find a way to use this to decrypt the ciphertext...
  block_size = 16
  num_blocks = len(ciphertext) // block_size + 1
  plaintext = b"" # we will build the plaintext here

  ct = iv + ciphertext
  blocks = [
    ct[i*block_size:(i+1)*block_size] for i in range(num_blocks)
  ]

  iv = blocks[0]
  for block in blocks[1:]:
    dec = single_block_attack(block, padding_oracle)
    plaintext += bytes_xor(iv, dec)
    iv = block
  return plaintext


def main():
  # generate random key + iv (we don't know these)
  key = os.urandom(16)
  iv = os.urandom(16)

  # choose random string
  plaintext = random.choice(random_strings).encode()

  # encrypt using CBC
  ciphertext = encrypt_cbc(plaintext, key, iv)
  print(f"Ciphertext: {ciphertext}")

  # get the padding oracle - decrypts and checks padding
  padding_oracle = get_padding_oracle(key)

  # This is the 'client' side
  # crack the ciphertext
  recovered = crack_cbc(iv, ciphertext, padding_oracle)
  recovered = remove_padding(recovered)
  print(f"Original: {plaintext.decode(errors='ignore')}")
  print(f"Recovered: {recovered.decode(errors='ignore')}")
  print(f"Decode: {base64.b64decode(plaintext).decode(errors='ignore')}")


if __name__ == "__main__":
  main()