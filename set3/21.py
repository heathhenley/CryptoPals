import random
# Set 3 Challenge 21
# implement MT19937
# https://en.wikipedia.org/wiki/Mersenne_Twister

class MT19937:
  # differs a little from pythons random module, need to look into that
  # a little, entirely using wiki for this implementation

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
      self.MT[i] &= self.lower_mask

  def extract_number(self):
    if self.index >= self.n:
      if self.index > self.n:
        raise Exception("Generator was never seeded")
      self._twist() 

    y = self.MT[self.index]
    y ^= (( y >> self.u) & self.d)
    y ^= (( y << self.s) & self.b)
    y ^= (( y << self.t) & self.c)
    y ^= ( y >> self.l)
    self.index += 1
    return y & self.lower_mask

  def _twist(self):
    for i in range(self.n):
      x = (self.MT[i] & self.upper_mask) | (
        self.MT[ (i+1) % self.n] & self.lower_mask )
      xA = x >> 1
      if x % 2 != 0:
        xA ^= self.a
      self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
    self.index = 0
  
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


def main():
  mt = MT19937(0)
  for _ in range(10):
    print(f"{mt.getrandbits(16):016b}")
  


if __name__ == "__main__":
  main()