# Set 3, Challenge 18: Implement CTR, the stream cipher mode
import base64
from Crypto.Cipher import AES
from common.utils import repeating_xor


def ctr_encrypt(
    pt_or_ct: bytes = None,
    key: bytes = None,
    nonce: int = 0) -> bytes:
  result = b""
  # for each block of the plaintext, generate a keystream, xor it
  for iblock in range(0, len(pt_or_ct), len(key)):
    keystream = ctr_key_stream(key, nonce, len(key))
    bend = min(iblock + len(key), len(pt_or_ct)) # last block may be shorter
    pt_block = pt_or_ct[iblock:bend]
    result += repeating_xor(pt_block, keystream)
    nonce += 1
  return result


def ctr_key_stream(key, nonce, block_size):
  nonce_bytes = nonce.to_bytes(8, byteorder="little")
  # pad nonce to block size with 0s (left padding as in example)
  nonce_bytes = b"\x00" * (block_size - len(nonce_bytes)) + nonce_bytes
  keystream = AES.new(key, AES.MODE_ECB).encrypt(nonce_bytes)
  return keystream


def main():
  # CTR mode:
  # - Encrypt a running counter (nonce) with AES-ECB to generate a "keystream"
  # - XOR the keystream with the plaintext to get the ciphertext
  # - Decrypt by XORing the ciphertext with the keystream
  #    - but you need to generate the same keystream
  test_str_base64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
  test_str = base64.b64decode(test_str_base64)
  print(test_str)

  test_key = b"YELLOW SUBMARINE"
  test_nonce = 0 # 64-bit unsigned integer (little-endian)
  decrypted = ctr_encrypt(pt_or_ct=test_str, key=test_key, nonce=test_nonce)
  print(decrypted)

if __name__ == "__main__":
  main()