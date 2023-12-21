import Crypto.Cipher.AES as AES
with open("8.txt", "r") as f:
  lines = f.readlines()
  ciphers = [bytes.fromhex(line.strip()) for line in lines]

# want to detect AES in ECB mode
# ECB mode: each block is encrypted independently, so if two blocks are the same
# in the plaintext, they will be the same in the ciphertext (and vice versa)
# so we can just look for repeated blocks and that's a good indicator of ECB
def detect_ecb(cipher):
  blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
  return len(blocks) != len(set(blocks))

def decrypt_ecb(cipher, key):
  return AES.new(key, AES.MODE_ECB).decrypt(cipher)

probably_ecb = []
for cipher in ciphers:
  if detect_ecb(cipher):
    probably_ecb.append(cipher)


print(f"Found {len(probably_ecb)} ECB ciphers")
for cipher in probably_ecb:
  print(cipher.hex())