# Cryptopals Set 2, Challenge 14 - Byte-at-a-time ECB decryption (Harder)
# same as 12, but with a random prefix of unknown length prepended to the
# plaintext before encryption, which adds some steps (eg we need to detect the
# prefix length first then we can crack like 12
import base64
import os
import secrets
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

  num_rand_bytes = secrets.randbelow(32)
  prefix = os.urandom(num_rand_bytes)
  
  def oracle_ecb(known: bytes) -> bytes:
    # encrypts known str with unknown using an unknown key using ECB mode
    return encrypt_ecb(
      prefix + known + base64.b64decode(unknown_base64), key)

  return oracle_ecb

def detect_block_size(oracle) -> int | None:
  # add bytes until the length of the ciphertext changes
  ct_nothing = oracle(b"")
  ct_current = ct_nothing
  i = 1
  while len(ct_current) == len(ct_nothing):
    ct_current = oracle(b"A" * i)
    i += 1
  return len(ct_current) - len(ct_nothing)

def detect_ecb(cipher: bytes, block_size: int = 16):
  return has_repeated_blocks(cipher, block_size)

def has_repeated_blocks(cipher: bytes, block_size: int = 16):
  blocks = [cipher[i:i+block_size] for i in range(0, len(cipher), block_size)]
  return len(blocks) != len(set(blocks))

def index_of_first_repeated_block(cipher: bytes, block_size: int = 16):
  blocks = [cipher[i:i+block_size] for i in range(0, len(cipher), block_size)]
  for i in range(len(blocks)):
    if blocks[i] in blocks[i+1:]:
      return i
  return -1

def detect_prefix_len(oracle: callable, block_size: int) -> int:
  """ Find the length of the unknown prefix prepended to the plaintext.

  Take two blocks of A's, and send them with X's prepended, to the oracle.
  When we find a repeated block in the ciphertext, we know that the prefix
  pushed our two blocks of A's so that they start on a new block.
  """

  two_blocks = b"A" * block_size * 2
  prefix_len = 0
  for i in range(block_size):
    ct = oracle( b"X" * i + two_blocks)
    if has_repeated_blocks(ct, block_size):
      prefix_len = block_size - i
      break # found it!
  
  # this is in case the prefix is longer than one block long
  prefix_end_idx = index_of_first_repeated_block(ct, block_size)

  return prefix_len + (prefix_end_idx - 1) * block_size

def get_ct_map(
    oracle,
    known_bytes: bytes,
    block_size: int,
    block_offset: int = 0) -> dict:
  start = block_offset * block_size
  end = start + block_size
  # Try all possible bytes for the last and only unknown byte in
  # the block, and store the ciphertexts in a map to be used later
  ct_map = {}
  for i in range(256):
    ct = oracle(known_bytes + bytes([i]))
    ct_map[ct[start:end]] = bytes([i])
  return ct_map

def crack_ecb(oracle: callable, block_size: int, prefix_len: int) -> bytes:
  """ Crack the oracle using ECB mode and a random prefix of unknown length. """

  # prefix is ending in
  prefix = b"X" * (block_size - prefix_len % block_size)

  print(f"Prefix: {prefix}")

  # block offset is the number of blocks in the prefix, we need to know which
  # block the unknown string starts in eg where the prefix part we don't care
  # about ends
  block_offset = (prefix_len  + len(prefix)) // block_size

  print(f"Block offset: {block_offset}")
  # get the unknown string length using the oracle with no input
  # with a block boundary
  lpad_oracle = lambda x: oracle(prefix + x)

  # just the ciphertext of the unknown string with the prefix and our padding
  ct_nothing = lpad_oracle(b"")
  unknown_str_len = len(ct_nothing)

  # accumulate the unknown string block by block
  unknown_str = b""

  # this is the test string we'll use to get the unknown string one byte at a
  # time, it's all A's except for the last byte which will get filled with the
  # byte we're trying to find
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
      ct = lpad_oracle(test_str)

      # get a map of all possible ciphertexts, only changing the
      # last byte of the test string
      ct_map = get_ct_map(
        lpad_oracle, test_str + unknown_block, block_size, block_offset)
      
      try:
        # look up the last byte of the ciphertext in the map
        bstart = bl_idx * block_size + block_offset * block_size
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
  if not detect_ecb(oracle(b"A" * 128)):
    print("ECB not detected!")
    return 1
  print("ECB detected!")

  # detect random padding length - but do I need to get the block size first?
  # Update there's a better method to get the block size than what I was using
  # before...
  if not (block_size := detect_block_size(oracle)):
    print("Block size not detected!")
    return 1
  print(f"Block size: {block_size}")

  prefix_len = detect_prefix_len(oracle, block_size)
  print(f"Prefix length: {prefix_len}")

  # crack it block by block
  unknown_str = crack_ecb(oracle, block_size, prefix_len) 
  print("Decoded:\n", unknown_str.decode(errors="ignore"))


def test():
  # Test with known "unknown string" and key for debugging 
  oracle = oracle_factory(
    key=b"YELLoW sUBMaRiNE",
    unknown_base64=base64.b64encode(b"YELLOW SUBMARINEYELLOW SUBMARINE").decode())
  print(crack_ecb(oracle, 16).decode())
  

if __name__ == "__main__":
  main()
  #test()