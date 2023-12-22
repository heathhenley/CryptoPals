import base64
import Crypto.Cipher.AES as AES


def decrypt_ecb(cipher, key):
  return AES.new(key, AES.MODE_ECB).decrypt(cipher)

def encrypt_ecb(plaintext, key):
  return AES.new(key, AES.MODE_ECB).encrypt(plaintext)

def repeating_xor(bstr: bytes, key: bytes):
  return bytes([b ^ key[i % len(key)]
                for i, b in enumerate(bstr)])

def xor(bstr: bytes, key: int):
  return bytes([b ^ key for b in bstr])

# Use XOR to convert ECB to CBC mode
# ECB mode: each block is encrypted independently
# CBC mode: each block is XORed with the previous ciphertext block before
# encryption

def encrypt_cbc(plaintext, key, iv):

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


def test():
  plaintext = b"YELLOW SUBMARINEs ARE COOL COOL!"
  key = b"YELLOW SUBMARINE"
  assert len(plaintext) % len(key) == 0 # having learned padding yet
  iv = bytes([0] * len(key))
  ciphertext = encrypt_cbc(plaintext, key, iv)
  decrypted = decrypt_cbc(ciphertext, key, iv)
  assert decrypted == plaintext

def main():
  with open("10.txt", "r") as f:
    ciphertext = base64.b64decode(f.read()) 

  key = b"YELLOW SUBMARINE"
  iv = bytes([0] * len(key))

  print(decrypt_cbc(ciphertext, key, iv).decode())

if __name__ == "__main__":
  test()
  main()