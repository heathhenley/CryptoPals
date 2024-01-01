# Cryptopals Set 2, Challenge 15 - PKCS#7 padding validation
def remove_padding(text: bytes):
  """ Remove padding from bytes - raise ValueError if padding is invalid """
  if len(text) == 0:
    raise ValueError("Invalid padding")
  padding = text[-1]
  if padding > len(text):
    raise ValueError("Invalid padding")
  for i in range(1, padding + 1):
    if text[-i] != padding:
      raise ValueError("Invalid padding")
  return text[:-padding]


def main():
  text = b"ICE ICE BABY\x04\x04\x04\x04"
  assert remove_padding(text) == b"ICE ICE BABY"

  try:
    text = b"ICE ICE BABY\x05\x05\x05\x05"
    remove_padding(text)
    assert False, "Should have raised ValueError"
  except ValueError:
    pass

  try:
    text = b"ICE ICE BABY\x01\x02\x03\x04"
    remove_padding(text)
    assert False, "Should have raised ValueError"
  except ValueError:
    pass

if __name__ == "__main__":
  main()