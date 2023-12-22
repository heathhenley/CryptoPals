def pad_to_n_bytes(s, n):
  if len(s) % n == 0:
    return s
  if len(s) > n:
    raise ValueError("String is longer than n bytes")
  pad_bytes = n - len(s) %  n
  return s + bytes([pad_bytes] * pad_bytes)

test = b"YELLOW SUBMARINE"
print(pad_to_n_bytes(test, 20))

