import base64
from Crypto.Cipher import AES

with open('7.txt', 'r') as f:
  cypertext = base64.b64decode(f.read())

key = b"YELLOW SUBMARINE"
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(cypertext).decode()
print(plaintext)