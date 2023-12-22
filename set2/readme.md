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
