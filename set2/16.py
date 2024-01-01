# Set 2, Challenge 16 - CBC bitflipping attacks
import os

import Crypto.Cipher.AES as AES


def pad_to_modn_bytes(s, n):
  if len(s) % n == 0:
    return s
  pad_bytes = n - (len(s) %  n)
  return s + bytes([pad_bytes] * pad_bytes)

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
  if len(plaintext) % len(key) != 0:
    raise ValueError("Plaintext must be multiple of key length")

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
    raise ValueError("Plaintext must be multiple of key length")

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

def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
  """ Encrypt plaintext under a random key, prefix and suffix """
  prefix = b'comment1=cooking%20MCs;userdata='
  suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
  plaintext = prefix + plaintext.replace(b";", b"").replace(b"=", b"") + suffix
  plaintext = pad_to_modn_bytes(plaintext, 16)
  return encrypt_cbc(plaintext, key, iv)


def main():
  iv = os.urandom(16)
  key = os.urandom(16)

  # Goal: create ciphertext that decrypts to ";admin=true;"

  # send a block of X's the same length as ";admin=true;"
  attack_str = b"?admin?true?"
  # get the ciphertext
  ct = bytearray(encrypt(attack_str, key, iv))

  # luckily the prefix is exactly two blocks long, so we don't
  # have to do any extra work to get the length right

  # this ciphertext block before the attack string will be XORed
  # with the attack string when decrypting - so we can modify the
  # ciphertext to make whatever changes we want to the plaintext

  # modify the ciphertext to get ";admin=true;"
  ct[16] ^= ord("?") ^ ord(";")
  ct[22] ^= ord("?") ^ ord("=")
  ct[27] ^= ord("?") ^ ord(";")

  # decrypt the modified ciphertext
  pt = decrypt_cbc(ct, key, iv)

  if b";admin=true;" in pt:
    print("Success!")
  else:
    print("Nope...")


if __name__ == "__main__":
  main()