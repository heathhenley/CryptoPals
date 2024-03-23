# Set 4, Challenge 29: Break a SHA-1 keyed MAC using length extension
import sha1


def sha1_mac(key: bytes, message: bytes) -> str:
  return sha1.sha1(key + message)


def sha1_mac_verify(key: bytes, message: bytes, mac: str) -> bool:
  return sha1_mac(key, message) == mac


# 'oracles' so we can pretend we don't know the key
def get_mac_generator(key: bytes) -> callable:
  # just wrap the sha1_mac function with the key
  return lambda message: sha1_mac(key, message)


def get_mac_verifier(key: bytes) -> callable:
  # just wrap the sha1_mac_verify function with the key
  return lambda message, mac: sha1_mac_verify(key, message, mac)

def md_pad(key_len_bytes: int, message: bytes) -> bytes:

  # get the length of the message in bytes and bits
  original_byte_len = len(message) + key_len_bytes
  message_len = original_byte_len * 8

  # append the bit '1' to the message
  message += b'\x80'
  # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
  #    is congruent to 448 (mod 512)
  message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)

  # append the length of the message in bits as a 64-bit big-endian integer
  message += message_len.to_bytes(8, 'big')

  return message

def main():
  # trusty old key
  key = b"YELLOW SUBMARINE"

  # test padding
  PAD_TEST = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\xe8'

  # mac generator with 'unknown' key
  mac_generator = get_mac_generator(key)

  # mac verifier with 'unknown' key
  mac_verifier = get_mac_verifier(key)

  # generate a mac for a message
  msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
  mac = mac_generator(msg)
  print(f"msg.mac: {msg.decode()}.{mac}")

  # check if the mac is valid (should return True, we just generated it)
  if mac_verifier(msg, mac):
    print("MAC is valid! (expected)")
  
  # test that md_pad works (we normally don't know the key,
  # this is just to test the padding function)
  if md_pad(len(key), msg) != PAD_TEST:
    assert False, "Padding is incorrect!"
  
  # modify the message, the mac should be invalid
  new_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true"
  if not mac_verifier(new_msg, mac):
    print("MAC is invalid after modification! (expected)")
  
  # Break the sha1 mac - length extension attack
  print("\nBreaking the SHA1 MAC using a length extension attack...")
  # original mac
  mac = mac_generator(msg) 

  # split the mac into 5 32-bit chunks to initialize the state
  state = [
    int.from_bytes(
      bytes.fromhex(mac[i:i+8]), byteorder='big')
      for i in range(0, 40, 8)
  ]

  # the evil string
  evil = b";admin=true"

  # we don't know the length of the key, so we'll just try some lengths
  for kl in range(1, 32):
    # get the padded message
    padded_msg = md_pad(kl, msg)
  
    # need to do this because we're changing the length and it's in the padding 
    total_pad_len = len(padded_msg) + kl

    # hash the evil string with state set to the original mac
    new_mac = sha1.sha1(evil, state=state, padding_offset=total_pad_len)

    # try to verify the whole evil message
    padded_msg += evil

    # check if the new mac is valid against the 'secret key'
    if mac_verifier(padded_msg, new_mac):
      print(f"  MAC is valid after modification with key length: {kl}")
      print(f"  Original MAC: {mac}")
      print(f"  New MAC: {new_mac}")
      print(f"  Original Message: {msg}")
      print(f"  Evil Message: {padded_msg}")
      break



  



if __name__ == "__main__":
  main()