import time
# Set 3 Challenge 23
# Clone an MT19937 RNG from its output
# Untemper them and stick them back in the state

class MT19937:

  # buncha constants
  f = 1812433253
  w, n, m, r = 32, 624, 397, 31
  a = 0x9908B0DF
  u, d = 11, 0xFFFFFFFF
  s, b = 7, 0x9D2C5680
  t, c = 15, 0xEFC60000
  l = 18

  def __init__(self, seed: int):
    # init 
    self.MT = [0] * self.n  # state

    # masking for 32 bit ints 
    self.lower_mask = (1 << self.r) - 1
    self.upper_mask = (1 << self.r)

    # index
    self.index = self.n + 1

    # init state for the first time
    self.seed_mt(seed)
  
  def seed_mt(self, seed: int):
    # Initialize the generator from a seed
    self.index = self.n
    self.MT[0] = seed
    for i in range(1, self.n):
      self.MT[i] = self.f * (
        (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i)
      self.MT[i] &= ((1 << self.w) - 1)

  def extract_number(self):
    if self.index > self.n:
      raise Exception("Generator was never seeded")
    if self.index == self.n:
      self._twist() 
    y = self._temper(self.MT[self.index])
    self.index += 1
    return y

  def _twist(self):
    for i in range(self.n):
      x = (self.MT[i] & self.upper_mask) | (
        self.MT[ (i+1) % self.n] & self.lower_mask )
      xA = x >> 1
      if x % 2 != 0:
        xA ^= self.a
      self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
    self.index = 0

  def _temper(self, y) -> int:
    # temper the output
    y ^= (( y >> self.u) & self.d)
    y ^= (( y << self.s) & self.b)
    y ^= (( y << self.t) & self.c)
    y ^= ( y >> self.l)
    return y & ((1 << self.w) - 1)
  
  def getrandbits(self, k: int) -> int:
    # get k random bits
    if k <= 0:
      raise ValueError("number of bits must be greater than zero")
    if k <= 32:
      # just get the last k bits of the number
      return self.extract_number() & ((1 << k) - 1)
    # we need to get more than 32 bits so we need to get
    # multiple random numbers      
    res = 0
    for i in range(k // 32):
      res <<= 32
      res |= self.extract_number()
    return res & ((1 << k) - 1) 


def untemper(y: int) -> int:
  """ Untemper the output of the MT19937 RNG.
  Used the excellent explanation here: https://occasionallycogent.com/inverting_the_mersenne_temper/index.html
  to wrap my head around all this bit manipulation.
  """
  smask = (1 << MT19937.s) - 1
  umask = (1 << MT19937.u) - 1
  lower_mask = (1 << MT19937.w) - 1
  y ^= (y >> MT19937.l)
  y ^= ((y << MT19937.t) & MT19937.c)
  y ^= ((y << MT19937.s) & MT19937.b & (smask << MT19937.s))
  y ^= ((y << MT19937.s) & MT19937.b & (smask << (MT19937.s * 2)))
  y ^= ((y << MT19937.s) & MT19937.b & (smask << (MT19937.s * 3)))
  y ^= ((y << MT19937.s) & MT19937.b & (smask << (MT19937.s * 4)))
  y ^= (y >> MT19937.u) & (umask << (MT19937.u * 2))
  y ^= (y >> MT19937.u) & (umask << MT19937.u)
  y ^= (y >> MT19937.u) & umask
  return y & lower_mask

def main():
  # make a new rng
  mt = MT19937(int(time.time()))

  # get 624 outputs
  outputs = [mt.extract_number() for _ in range(624)]

  # untemper them
  untempered = [untemper(x) for x in outputs]

  # make a new rng, set the state to the untempered outputs
  clone = MT19937(0)
  clone.MT = untempered

  # check that clone works:
  for _ in range(100):
    x, y = mt.extract_number(), clone.extract_number()
    assert x == y, "untempered rng failed"
  
  print("MT cloned!")

  

def test_untemper():
  mt = MT19937(1)
  for i in range(100):
    x = mt.extract_number()
    assert mt._temper(untemper(x)) == x, f"untemper failed {i, x}"

if __name__ == "__main__":
  test_untemper()
  main()