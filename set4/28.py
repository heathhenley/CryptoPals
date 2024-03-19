import sys

import sha1


def sha1_mac(key: bytes, message: bytes) -> str:
  return sha1.sha1(key + message)


def sha1_mac_verify(key: bytes, message: bytes, mac: str) -> bool:
  return sha1_mac(key, message) == mac


def main():
  key = b"YELLOW SUBMARINE"
  msg = b"Hello World!"
  mac = sha1_mac(key, msg)
  print(f"msg.mac: {msg.decode()}.{mac}")

  # check if the mac is valid (should return True, we just generated it)
  assert sha1_mac_verify(key, msg, mac)

  # modify the message, the mac should be invalid
  msg = b"Hello World?"
  assert not sha1_mac_verify(key, msg, mac)


if __name__ == "__main__":
  main()