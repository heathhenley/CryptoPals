# Challenge 21 

Jumping to this challenge because it seems that understanding MT19937 and how
works under the hood might help me with another crypto challenge I'm working on
right now. Specifically need a good understanding of how state is related to
the seed, etc.

Not matching Python implementation for the same seed, not sure if it's because
it's implemented differently or if I'm doing something wrong, going to look
into it more...

Giving us random (looking) numbers though, so that's cool!

Update: it's not matching python because they init first with a fixed int seed,
and then re-init with the seed we provide - so I would need to implement that to
match it exactly.

Completed the attack part Challenge 22 - I used my implementation of MT19937
and python's random module seeded with time. So I think that demonstrates that
I'm at least understanding the idea:
- if MT is seeded with a single int (or a small number of ints like python)
  we can pretty much brute force seeds until we find the right one
- if MT state is completely initialized using /dev/urandom or something, we're
  not going to be able to do that for the seed, but it's still possible to
  predict the next number in the sequence if we have enough numbers from the
  sequence (624) (this is next challenge)

Python does something fancy - it seeds normally as it describes in wiki with a
single int, but then it re-seeds using repetition of the seed we gave it to
initialize the state.
Eg: https://github.com/python/cpython/blob/main/Modules/_randommodule.c#L225 
(init_genrand is the normal seeding - then there is a loop
updates the state with repetitions of 32bit chunks of the seed)

# Challenge 23

I was pretty stuck on the bit operations for this one, but I searched around and
found some great examples of how to do it. There were are lot of examples of
a symbolic solver to solve it, but I think it's more interesting to see it
actually implemented as reversing each operation.
