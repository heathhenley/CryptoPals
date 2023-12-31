import hmac
import time
import random

# oracle like function to generate a random key and hmac of a message that
# uses a poorly seeded mt19937 and that us "unknown" to the attacker
def hmac_md5_random_key(
    msg: bytes, max_time_delta: int, max_iters: int) -> str:
  """ Generate a random key, use it to generate an hmac of the message

  The RNG is seeded with the current time some time in the past, and has been
  called some random number of times before the key was generated. The maxes
  for those are controlled with max_time_delta and max_iters, respectively.
  """
  seed = int(time.time()) - random.randint(0, max_time_delta)

  # Separate instance of the RNG so we don't mess with the global one
  mt = random.Random(seed)
  
  # extract some numbers to make things more difficult
  for _ in range(random.randint(0, max_iters)):
    mt.getrandbits(32)

  # actual random key
  key = mt.getrandbits(256)
  return hmac.new(key.to_bytes(32), msg, digestmod="md5").hexdigest(), seed


def get_valid_keys(vals: list, key_size: int = 256) -> list:
  # the key is 256 bits, so if someone pulled another number from the rng
  # in between generating the key, we might miss it when we try to brute force
  # because if we simply call getrandbits(256) we will pull 8 numbers from the
  # rng - we will only detect the right seed in multiples of 8 unless we try
  # all the possible offsets

  assert key_size % 32 == 0, "key size must be a multiple of 32 - for now"

  # we need to try all the possible offsets to make key_size bits
  vals_in_key = key_size // 32

  # start with any val as the first one
  # fill from lsb to msb (from python source for getrandbits)
  for i in range(len(vals)-vals_in_key+1):
    key = vals[i]
    for j in range(1, vals_in_key):
      key |= (vals[i+j] << (32 * j))
    yield key


def test_attack():
  # Test attack - More or less, this is Set 3 Challenge 22
  # I've modified it to practice for another challenge, eg using HMACs made
  # from key = getrandbit() instead of only the numbers generated by the RNG
  # and the python mt19937 instead of my own implementation (because I have to
  # use the python one for the challenge)

  # The testing 'oracle'
  #  - unknown random key (256 bits) using a poorly seeded mt19937
  #  - use it to HMAC our test message 
  #  - we don't know the key, or how many times the RNG was called before we
  #    the key was generated, but we know it was seeded 'poorly', and that it
  #    is MT19937 obviously
  msg = b"this is a test message"
  target, actual_seed = hmac_md5_random_key(
    msg, max_time_delta=500, max_iters=100)
  
  print(f"msg:mac - {msg.decode()}:{target}")
  print("  actual seed: ", actual_seed)

  # Brute force the RNG seed and key:
  # - pull extract_per_seed numbers from the rng and use them to make keys
  # - hmac the msg with the key and see if it matches the target mac
  extract_per_seed = 1000
  k = 0
  # brute force the seed and key, start at now and go backwards
  for seed in range(int(time.time()), 0, -1):

    # set up with the seed we want to test
    random.seed(seed)

    # extract depth 32 bit ints from the rng and use them to make keys
    vals = [random.getrandbits(32) for _ in range(extract_per_seed)]

    for key in get_valid_keys(vals, 256):
  
      # get hmac of plaintext using key (little endian)
      h = hmac.new(key.to_bytes(32, "little"), msg, digestmod="md5")
      if h.hexdigest() == target:
        print(f"found seed: {seed}, key: {key}, little endian")
        return

      # get hmac of plaintext using key (big endian)
      h = hmac.new(key.to_bytes(32, "big"), msg, digestmod="md5")
      if h.hexdigest() == target:
        print(f"found seed: {seed}, key: {key}, big endian")
        return

      if k % 100_000 == 0:
        print(k, seed, actual_seed)

      if seed < actual_seed:
        print("you missed it :(")
        return

      k += 1


if __name__ == "__main__":
  #main()
  test_attack()