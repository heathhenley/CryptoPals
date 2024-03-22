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
    return s
  pad_bytes = n - (len(s) %  n)
  return s + bytes([pad_bytes] * pad_bytes)

def remove_padding(text: bytes):
  """ Remove padding from bytes - raise ValueError if padding is invalid """
  if len(text) == 0:
    raise ValueError("Invalid padding")
  padding = text[-1]
  if padding > len(text):
    raise ValueError("Invalid padding")
  for i in range(1, padding + 1):
    if text[-i] != padding:
      raise ValueError("Invalid padding")
  return text[:-padding]

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

def get_padding_oracle(ciphertext, key, iv):

  def decrypt_and_check_padding(ciphertext):
    """ Decrypt ciphertext, and check padding """
    plaintext = decrypt_cbc(ciphertext, key, iv)
    try:
      plaintext = remove_padding(plaintext)
      return True
    except ValueError:
      return False
  return decrypt_and_check_padding

def crack_cbc(ciphertext: bytes, padding_oracle: callable):
  """ Crack CBC using padding oracle """
  return padding_oracle(ciphertext)


def main():
  # generate random key + iv
  key = os.urandom(16)
  iv = os.urandom(16)

  # choose random string
  plaintext = base64.b64decode(random_strings[random.randint(0,9)])

  # encrypt using CBC
  ciphertext = encrypt_cbc(plaintext, key, iv)

  # get the padding oracle - decrypts and checks padding
  padding_oracle = get_padding_oracle(ciphertext, key, iv)

  # this is the 'client' side
  # crack the ciphertext
  res, plaintext = crack_cbc(ciphertext, padding_oracle)

if __name__ == "__main__":
  main()