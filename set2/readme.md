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
