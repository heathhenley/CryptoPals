# Problems 1 - 5
Pretty straightforward.

# Problem 6
This was a cool one! I had some trouble with the wording of the problem,
basically it works better to find distance the i'th with the i+1'th block
over the whole ciphertext, for your potential block size and average. Then
use the key size with the best average as your key. It reads like it's just 
block 1 and 2, which doesn't work.

It's also confusing that is says "split in to blocks" and then "split into
blocks" again, when referring to taking the i'th byte of each block to find
the i'th byte of the key. I found it easier to think about it as just taking
i'th byte of each block and repeating. 🤷‍♂️

# Problem 7 + 8
Cool!