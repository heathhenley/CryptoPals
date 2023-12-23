# Cryptopals Set 2, Challenge 12
import base64
import os
import Crypto.Cipher.AES
from Crypto.Cipher.AES import MODE_CBC, MODE_ECB


UNKNOWN = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"


def encrypt_ecb(bstr: bytes, key: bytes) -> bytes:
  if len(bstr) % len(key) != 0:
    pad_bytes = len(key) - len(bstr) % len(key)
    bstr += bytes([pad_bytes] * pad_bytes)
  cipher = Crypto.Cipher.AES.new(key, MODE_ECB)
  return cipher.encrypt(bstr)

def oracle_factory(
    key: bytes = os.urandom(16),
    unknown_base64: str = UNKNOWN) -> callable:
  """ Returns a an 'oracle' that uses ecb mode random key

  It appends the unknown string to the user's input and encrypts them
  together.
  """
  def oracle_ecb(known: bytes) -> bytes:
    # encrypts known str with unknown using an unknown key using ECB mode
    return encrypt_ecb(
      known + base64.b64decode(unknown_base64), key)
  return oracle_ecb

def detect_block_size(oracle) -> int | None:
  ct_nothing = oracle(b"") # this is the ct for the secrect unknown string
  for i in range(1, 32):
    known = b"A" * i
    ct = oracle(known)
    # does the first block of ct_nothing match the second block of ct?
    if ct_nothing[:i] == ct[i:2*i]:
      return i
  return None

def detect_ecb(cipher):
  blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
  return len(blocks) != len(set(blocks))

def get_ct_map(oracle, known_bytes: bytes, block_size: int) -> dict:
  # Try all possible bytes for the last and only unknown byte in
  # the block, and store the ciphertexts in a map to be used later
  ct_map = {}
  for i in range(256):
    ct = oracle(known_bytes + bytes([i]))
    ct_map[ct[:block_size]] = bytes([i])
  return ct_map

def crack_ecb(oracle, block_size: int) -> bytes:

  # get the unknown string length using the oracle with no input
  ct_nothing = oracle(b"")
  unknown_str_len = len(ct_nothing)

  unknown_str = b""
  test_str = b"A" * (block_size - 1) 
  for bl_idx in range(unknown_str_len // block_size):
    # get the test string for this block, at first it's all A's
    # then we use the last block
    if bl_idx > 0:
      test_str = unknown_str[-(block_size - 1):] # last block_size - 1 bytes

    # how much remains of the unknown string?
    unknown_str_rem = unknown_str_len - len(unknown_str)

    # crack the blocks one by one
    unknown_block = b"" 
    while len(unknown_block) < min(unknown_str_rem, block_size):

      # send the test string, and get the ciphertext
      ct = oracle(test_str)

      # get a map of all possible ciphertexts, only changing the
      # last byte of the test string
      ct_map = get_ct_map(
        oracle, test_str + unknown_block, block_size)
 
      try:
        # look up the last byte of the ciphertext in the map
        bstart = bl_idx * block_size
        bend = bstart + block_size
        unknown_byte = ct_map[ct[bstart:bend]]
      except KeyError:
        # we've reached the end of the unknown string, or there's
        # at least some byte(s) that we don't recognize
        break

      # found another byte, add to the unknown block we're building
      unknown_block += unknown_byte

      # update the test string for next iteration
      test_str = test_str[1:]
  
    unknown_str += unknown_block
  return unknown_str


def main():
  # make a new oracle function
  oracle = oracle_factory()

  # detect that it's using ECB mode
  if not detect_ecb(oracle(b"A" * 100)):
    print("ECB not detected!")
    return 1
  print("ECB detected!")

  # detect block size
  if not (block_size := detect_block_size(oracle)):
    print("Block size not detected!")
    return 1
  print(f"Block size: {block_size}")

  # crack it block by block
  unknown_str = crack_ecb(oracle, block_size) 
  print("Decoded:\n", unknown_str.decode())


def test():
  # Test with known "unknown string" and key for debugging 
  oracle = oracle_factory(
    key=b"YELLoW sUBMaRiNE",
    unknown_base64=base64.b64encode(b"YELLOW SUBMARINEYELLOW SUBMARINE").decode())
  print(crack_ecb(oracle, 16).decode())
  

if __name__ == "__main__":
  main()
  #test()