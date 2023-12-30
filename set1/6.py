# Cryptopals Set 1, Challenge 6 - Break repeating-key XOR
# - uses hamming distance to find key size and letter frequency to find key
import base64

def xor(bstr: bytes, key: int):
  return bytes([b ^ key for b in bstr])

def repeating_xor(bstr: bytes, key: bytes):
  return bytes([b ^ key[i % len(key)]
                for i, b in enumerate(bstr)])

def hamming_distance(bstr1: bytes, bstr2: bytes):
  return sum([bin(b1 ^ b2).count("1")
              for (b1, b2) in zip(bstr1, bstr2)])

def score(bstr: bytes):
  # https://en.wikipedia.org/wiki/Letter_frequency
  freq = {
      'a': 0.08167,
      'b': 0.01492,
      'c': 0.02782,
      'd': 0.04253,
      'e': 0.12702,
      'f': 0.02228,
      'g': 0.02015,
      'h': 0.06094,
      'i': 0.06966,
      'j': 0.00153,
      'k': 0.00772,
      'l': 0.04025,
      'm': 0.02406,
      'n': 0.06749,
      'o': 0.07507,
      'p': 0.01929,
      'q': 0.00095,
      'r': 0.05987,
      's': 0.06327,
      't': 0.09056,
      'u': 0.02758,
      'v': 0.00978,
      'w': 0.02360,
      'x': 0.00150,
      'y': 0.01974,
      'z': 0.00074,
      ' ': 0.13000,
  }
  return sum([freq.get(chr(b), 0) for b in bstr.lower()])
  
def best_score(bstr: bytes, top_n: int = 1):
  # Returns [(key, score, result), ...]
  results = [(i, score(xor(bstr, i)),
              xor(bstr,i)) for i in range(0, 256)]
  results.sort(reverse=True, key=lambda x: x[1])
  return results[:top_n]

def best_key_sizes(
    min_key_size: int, max_key_size: int, bstr: bytes,
    top_n: int = 1):
  # Returns key size, distance
  key_dist = []
  for key_size in range(min_key_size, max_key_size + 1):
    scores = []
    if len(bstr) < 2 * key_size:
      break
    for i in range(0, len(bstr) // key_size - 1):
      # compare the ith and (i+1)th blocks
      b1 = bstr[i*key_size:(i+1)*key_size]
      b2 = bstr[(i+1)*key_size:(i+2)*key_size]
      score = hamming_distance(b1, b2) / key_size
      scores.append(score)
    key_dist.append((key_size, sum(scores) / len(scores)))
  key_dist.sort(key=lambda x: x[1])
  return key_dist[:top_n]


def crack_rkey_xor(
    bstr: bytes, min_key_size: int, max_key_size: int, top_n: int = 3):
  """ Crack repeating key XOR using hamming distance and letter frequency

  Try key sizes from min_key_size to max_key_size, and return the top_n results
  ."""
  candidates = best_key_sizes(
    min_key_size, max_key_size, bstr, top_n)
  res = []
  for key_size, _ in candidates:
    # take the first byte of each block, then the second byte, etc.
    key = []
    for i in range(key_size): # get the ith byte of key
      best_key = None 
      best_s = 0
      for bidx in range(0, len(bstr) // key_size):
        block = bstr[bidx * key_size + i::key_size]
        k, s, _ = best_score(block)[0]
        if s > best_s:
          best_key = k
          best_s = s
      key.append(best_key)
    txt = repeating_xor(bstr, key)
    rk = bytes(key).decode("utf-8", errors="ignore")
    res.append((score(txt), rk, repeating_xor(bstr, bytes(key))))
  return sorted(res, reverse=True, key=lambda x: x[0])


def main():
  with open("6.txt", "r") as f:
    bstr = base64.b64decode(f.read())

  res = crack_rkey_xor(bstr, min_key_size=2, max_key_size=40)

  for score, key, _ in res:
    print(score, key)

  print() 
  print(f"Best result {res[0][0]:.1f} with key {res[0][1]}:")
  print(res[0][2].decode("utf-8", errors="ignore"))

def test():
  b1 = b'this is a test'
  b2 = b'wokka wokka!!!'
  assert 37 == hamming_distance(b1, b2)


if __name__ == "__main__":
  main()