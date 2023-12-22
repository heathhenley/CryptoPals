import os
import Crypto.Cipher.AES
from Crypto.Cipher.AES import MODE_CBC, MODE_ECB


def detect_ecb(cipher):
  blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
  return len(blocks) != len(set(blocks))

def get_random_bytes(n: int) -> bytes:
  return os.urandom(n)

def get_rand(start: int, end: int) -> int:
  return int(get_random_bytes(1).hex(), 16) % (end - start) + start

def add_random_bytes(bstr: bytes, block_size: int = 16) -> bytes:
  # adds 5-10 random bytes before and after bstr
  nbytes_before = get_rand(1, block_size - 6)
  nbytes_after = 16 - nbytes_before
  return get_random_bytes(nbytes_before) + bstr + get_random_bytes(nbytes_after)

def encryption_oracle(bstr: bytes, key_size: int = 16) -> bytes:
  # Randomly encrypts bstr with either ECB or CBC
  # Adds 5-10 random bytes before and after bstr
  # Returns key, mode, ciphertext - key and mode
  # are for debugging purposes (eg confirm detection
  # of ECB mode is working)

  if len(bstr) % key_size != 0:
    raise ValueError("bstr is not a multiple of key_size")

  # add rando's
  bstr = add_random_bytes(bstr, key_size)

  # encrypt w/ ECB or CBC randomly, with unknown key
  key = get_random_bytes(key_size)
  if int(get_random_bytes(1).hex(), key_size) % 2 == 0:
    iv = get_random_bytes(key_size)
    cipher = Crypto.Cipher.AES.new(key, MODE_CBC, iv)
    return key, MODE_CBC, cipher.encrypt(bstr)
  cipher = Crypto.Cipher.AES.new(key, MODE_ECB)
  return key, MODE_ECB, cipher.encrypt(bstr)

def detect_mode(
    ciphertext: bytes, block_size: int = 16) -> MODE_CBC | MODE_ECB:
  if len(ciphertext) % block_size != 0:
    raise ValueError("ciphertext is not a multiple of block_size")
  return MODE_ECB if detect_ecb(ciphertext) else MODE_CBC

def main():
  key_size = 16
  k, m, ct = encryption_oracle(b"YellOw SUbmarine", key_size)
  print(f"mode: {m}, detected: {detect_mode(ct)}")


if __name__ == "__main__":
  main()