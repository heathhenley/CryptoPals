# Problem 9
This was straightforward - interesting to learn that it's padded
with the number of bytes added as the padding, I didn't know that.

# Problem 10
This was also interesting! I'm having trouble with the wording of
these sometimes, but I feel it might be intentional so that you
have to work for it more.

ECB mode - each block is encrypted independently, so blocks of the
plaintext that the same will be encrypted to the same ciphertext.

CBC mode - each plaintext block is (repeating key) XORed with the
previous ciphertext block before being ECB encrypted.

Decrypting the ciphertext is the reverse of this process.

# Problem 11
Made an encryption oracle that randomly chooses between ECB and CBC
and encrypts the plaintext with a random key and IV along with a
simple function to detect ECB mode.

# Problem 12
Actually going to crack ECB mode given that there is an oracle that
can call with an arbitrary plaintext and get the ciphertext back.

Find the key size (even though we know it's 16) by first getting
the ciphertext of only the unknown string. Then, add a byte at a
time to be encrypted with the unknown string. So b"A", b"AA", b"AAA",
etc. until the second block of the ciphertext matches the first block
of the original ciphertext (with no added bytes). This is the key
size!

Then we find the unknown string by:
 1. Send 1 byte less than a block size of A's
    - the oracle will encrypt the A's and the first byte of the unknown
      string together.
    - Check all possibilities AAAA...A0, AAAA...A1, AAAA...A2, etc,
      until we find a match, that's the first byte of the unknown string!
 2. Send 2 bytes less than a block size of A's + the first byte of the
    unknown string we found in step 1, and repeat step 1 to find the
    second byte of the unknown string.
 3. Repeat until we've found all the bytes of the unknown string.

# Problem 13

Haven't got it working yet, but I started by sending a bunch of X's followed by
a bunch of A's in multiples of the block size, and then I adjusted the X's
until I had that many repeated block of A's in the ciphertext. Eg 10 X's, and
that fills the block so that with 32 A's, we then get 2 blocks of A's in the
ciphertext (eg the blocks are repeated). We can use that to get the ciphertext
for anyblock we want in the middle.

This is what I think I have to do:
- get the ciphertext for just 'user' alone in a block (with padding)
- add a bunch of A's to the email field until the 'user' ciphertext block shows
  up in the ciphertext (so it means we pushed it to be the last block)
- then we can get the ciphertext for 'admin' alone in a block (with padding) 
  using the A's, to make sure it's in a block by itself, like we did with 'user'
- then we can replace the last block of the ciphertext, that has 'user' in it,
  with the ciphertext for 'admin' alone in a block (with padding)
- then we can decrypt the ciphertext and get the admin role!

So far, I am pushing the 'user' block to the end, but I'm not getting the same
ciphertext that I get when when I stick in between the A's - I think I'm doing
something wrong with the padding.

Update: Just got it working, it was the padding value that was wrong - that's
what I get for poking around and doing it 'by hand' instead of generalizing a
bit more. The approach above is what I ended up doing, and it worked!

# Problem 14
This is the same as 12, but with a random number of random bytes prepended to
the plaintext before it's encrypted. Need to first update to get block size in
a different way, the prefix breaks the way I was using before.

So:
- get block size (add a's until the size of ct changes size)
- get len of prepended bytes add two blocks of A's, prepend with an adjusting
  number of X's until there are two repeated blocks in the ciphertext - that
  number of X's pushed the A's to the block after the prepended bytes + X's
- ah then the length of the prepended bytes is the something like:
  block size * (block idx - 1) + (block size - len of X's)

This more or less worked - I was stuck for a little while because I messed up
the block offset - now that there is a random prefix, the unknown part that we
care about decrypting is is not at the first block, it's in the block after the
the prefix ends (we add X's to fill up the prefix's block). Then it's basically
the same as before (number 12)

# Problem 15

Seemed pretty straightforward - I think it's just needed for the next one.