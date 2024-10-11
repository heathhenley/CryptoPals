# Set 3, Challenge 20: Break fixed-nonce CTR mode statistically
import base64
import pathlib
from Crypto.Cipher import AES

from common.utils import repeating_xor, crack_rkey_xor


# From challenge 18:
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


def get_char_freq(text: str) -> dict:
  freq = {}
  for c in text.lower():
    if c in freq:
      freq[c] += 1
    else:
      freq[c] = 1
  total = sum(freq.values())
  for c in freq:
    freq[c] /= total
  return freq


def main():
  # Breaking CTR with a fixed nonce part 2 (challenge 20)
  # - all the cipher texts are encrypted with the same key and nonce
  # - the first block of each cipher text is encrypted with the same keystream

  # get script dir and open the file using pathlib
  script_dir = pathlib.Path(__file__).parent.absolute()
  test_file = script_dir / "20.txt"

  with open(test_file, "r") as f:
    example_texts_base64 = f.readlines()

  key = b"YELLOW SUBMARINE"
  nonce = 0
  texts = [base64.b64decode(text) for text in example_texts_base64]
  cipher_texts = [ctr_encrypt(text, key, nonce) for text in texts]

  # Turns out the CTR with a fixed nonce and key is basically the same as
  # repeating-key XOR, so we can use the same technique we used in the
  # ealier challenges to break it. From the problem statement:
  #   - truncate all the cipher texts to the length of the shortest one
  #   - concatenate the cipher texts
  #   - break the repeating-key XOR (with key size equal to the shortest one)
  shortest_len = min(len(ct) for ct in cipher_texts)
  print("Shortest length:", shortest_len)
  cipher_texts_cat = b"".join([ct[:shortest_len] for ct in cipher_texts])
  res = crack_rkey_xor(
    cipher_texts_cat,
    min_key_size=shortest_len,
    max_key_size=shortest_len,
    top_n=3)[0]
  for score, key, plain_text in res:
    print("Cracked score:", score)
    print("Cracked key:", key)
    print("Length of cracked key:", len(key))
    # print shortest len chunks of the plain text to compare
    for i in range(0, len(plain_text), shortest_len):
      print(plain_text[i:i+shortest_len])
      print(texts[i // shortest_len][:shortest_len])
      print()
      if i // shortest_len > 5:
        break



if __name__ == "__main__":
  main()