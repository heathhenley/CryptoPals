def xor(bstr: bytes, key: int):
  return bytes([b ^ key for b in bstr])

def repeating_xor(bstr: bytes, key: bytes):
  return bytes([b ^ key[i % len(key)] for i, b in enumerate(bstr)])

test_str = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
print(repeating_xor(test_str, b"ICE").hex())