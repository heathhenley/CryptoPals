# Set 3, Challenge 19: Break fixed-nonce CTR mode using substitutions
import base64
from Crypto.Cipher import AES

from common.utils import repeating_xor, score


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


example_texts_base64 = [
  "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
  "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
  "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
  "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
  "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
  "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
  "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
  "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
  "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
  "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
  "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
  "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
  "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
  "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
  "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
  "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
  "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
  "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
  "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
  "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
  "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
  "U2hlIHJvZGUgdG8gaGFycmllcnM/",
  "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
  "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
  "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
  "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
  "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
  "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
  "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
  "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
  "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
  "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
  "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
  "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
  "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
  "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
  "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
  "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
]


def main():
  # Breaking CTR with a fixed nonce
  # - all the cipher texts are encrypted with the same key and nonce
  # - the first block of each cipher text is encrypted with the same keystream

  # First encrypt all the example texts with the same key and nonce (not in
  # one stream, but with the nonce starting at 0 for each text)

  print("Example texts:")
  for text in example_texts_base64:
   print(base64.b64decode(text))

  key = b"YELLOW SUBMARINE"
  nonce = 0
  cipher_texts = [ctr_encrypt(base64.b64decode(text), key, nonce)
                  for text in example_texts_base64]

  # Now we have the cipher texts, we can try to break them, assuming we don't
  # know the key or nonce. We will try to break them using substitutions...
  # - we can try to find the most common byte in each position

  # Now we have the possible guesses for each byte of the keystream, we can test
  # them by xor'ing against the first block of each cipher text
  def generate_possible_keystreams(guesses, index=0, current=[]):
    if index == 16:
      yield b"".join(current)
      return
    for guess in guesses[index]:
      current.append(guess)
      yield from generate_possible_keystreams(guesses, index+1, current)
      current.pop()

  # Crack block by block, for all texts
  shortest = min(len(cipher) for cipher in cipher_texts)
  best_keystream_per_block = []
  for iblock in range(0, shortest, 16):
    print(f"Block {iblock}")
    # guess each byte of the keystream by finding bytes that seem to make sense 
    # for all the cipher texts, just substitute in byte by byte
    possible_guesses = {}
    for byte_index in range(16):
      possible_guess = []
      # try all possible bytes
      for guess in range(256):
        # check if the guess is a good one (all the results are printable)
        good_guess = True
        for cipher_text in cipher_texts:
          if iblock + byte_index >= len(cipher_text):
            continue
          decrypted = chr(cipher_text[iblock + byte_index] ^ guess)
          if not decrypted.isprintable():
              good_guess = False
              break
          if decrypted.lower() not in "abcdefghijklmnopqrstuvwxyz-. ,:;\"?!'":
            good_guess = False
            break
        if good_guess:
          possible_guess.append(bytes([guess]))
      possible_guesses[byte_index] = possible_guess

    max_score = 0
    best_guess = None
    for keystream in generate_possible_keystreams(possible_guesses):
        sum_score = 0
        for cipher_text in cipher_texts:
          res = repeating_xor(cipher_text[iblock:16+iblock], keystream)
          sum_score += score(res)
          # make it costly if it doesn't start with a capital letter
          if iblock == 0 and chr(res[0]).islower():
            sum_score -= 1000
        if best_guess is None or sum_score > max_score:
          max_score = sum_score
          best_guess = keystream
    print(f"Score: {max_score}, keystream: {keystream}")
    best_keystream_per_block.append(best_guess)


  # Nice - use the probable keystream for each block to see what we got!
  plain_texts = []
  for cipher_text in cipher_texts:
    pt = b""
    for iblock in range(0, shortest, 16):
      keystream = best_keystream_per_block[iblock // 16]
      end = min(iblock + 16, len(cipher_text))
      pt += repeating_xor(cipher_text[iblock:end], keystream)
    plain_texts.append(pt)
  print("Decrypted texts:")
  for text in plain_texts:
    print(text)


if __name__ == "__main__":
  main()