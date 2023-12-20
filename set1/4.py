
def xor(bstr: bytes, key: int):
  return bytes([b ^ key for b in bstr])

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
  results = [(score(xor(bstr, i)), xor(bstr,i)) for i in range(0, 256)]
  results.sort(reverse=True)
  return results[:top_n]

def main():
  with open("4.txt", "r") as f:
    hexstrs = [x.strip() for x in f.readlines()]
    best = -1
    best_res = None
    best_hex = None
    for hexstr in hexstrs:
      bstr = bytes.fromhex(hexstr)
      s, r = best_score(bstr, 1)[0]
      if s > best:
        best = s
        best_res = r
        best_hex = hexstr
    print(best_res, best, best_hex)

if __name__ == "__main__":
  main()
