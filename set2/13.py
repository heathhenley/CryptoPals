# Set 2 Challenge 13 - Cut and Paste Attack
import os
import Crypto.Cipher.AES
from Crypto.Cipher.AES import MODE_ECB

def parse_kv(s: str) -> dict:
  return {k: v for k, v in [kv.split("=") for kv in s.split("&")]}

def profile_for(
    email: str = "foo@bar.com",
    uid: int = 10,
    role: str = "user") -> str:
  email = email.replace("&", "").replace("=", "")
  return f"email={email}&uid={uid}&role={role}"

def encrypt_ecb(bstr: bytes, key: bytes) -> bytes:
  if len(bstr) % len(key) != 0:
    pad_bytes = len(key) - len(bstr) % len(key)
    bstr += bytes([pad_bytes] * pad_bytes)
  cipher = Crypto.Cipher.AES.new(key, MODE_ECB)
  return cipher.encrypt(bstr)

def decrypt_ecb(bstr: bytes, key: bytes) -> bytes:
  cipher = Crypto.Cipher.AES.new(key, MODE_ECB)
  return cipher.decrypt(bstr)

def oracle_factory(key: bytes = os.urandom(16)) -> callable:
  def oracle_ecb(email: str) -> bytes:
    return encrypt_ecb(profile_for(email).encode(), key)
  return oracle_ecb


def main():
  key = b"YELLOW SUBMARINE" #os.urandom(16)
  oracle = oracle_factory(key=key)

  # got these by trial and error basically, once you know the block size you
  # can just pad the email so you know you are getting full blocks back, and
  # stick whatever you want in the middle w/ padding to get the ciphertext
  ct_user = b'\x83N\xca5}\xd8\xeb\xe6\xf9v\xc6=\x96a\nP' 
  ct_admin = b'\xf8\x8c\x0e9:\xa9\x11\xdf\xfa\xb1MV\x8ays='
  # move 'user' to the block boundary using a long email, then replace the ct of
  # the last block with the ct of 'admin' to get the admin role
  # this was the trial and error part, I changed the bounds of the four loop
  # to make 'user' end up in the last block - turned out to be an offset of 13
  for j in range(3, 4): 
    ct_for_attacker = oracle("X" * 10 + 'A' * j)
    print(ct_for_attacker)
    for i in range(len(ct_for_attacker) // 16):
      start = i * 16
      end = (i + 1) * 16
      block = ct_for_attacker[start:end]
      print(block)
      if block == ct_user:
        print(f"found user ct, block: {i}, offset: {j}")
        break
  
  # Actually do the attack now that we know the offset and the ciphertext:
  original = oracle("X" * 10 + 'A' * 3)

  # swap the last block of the original with the admin block
  modified = original[:-16] + ct_admin

  # decrypt the modified ciphertext to see if it worked...
  plaintext = decrypt_ecb(modified, key)
  print(parse_kv(plaintext.decode()))


if __name__ == "__main__":
  main()