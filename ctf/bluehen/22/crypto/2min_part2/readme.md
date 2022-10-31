# Problem: 

OK, I wrote this problem in two minutes. I think it should take you no more than 10 hours.

0037bf7c229d58a1fdb2eca0276f2bc20e2094a91c010e42a564fcc0b07a4913 is the sha256 hash of two words from the scrabble dictionary separated by a single space. I've attached my dictionary which has 187632 words.

For instance sha256("surrounding matt") gives 53d32f9c0e84a34dc5eb4708fd63770236e5be614a3e099cef83433b559624a6.

The flag format is UDCTF{WORD1_WORD2}

Author: ProfNinja

# Solution:

Solution was simple brute force.  I started the script 10 min before the CTF
ended so I had no hope in completing it in time.  The category said "parallel"
so I suspect an even better / faster solution would have probably been to use
a GPU / CUDA since they are so good at hashing. My slow script was done when I
checked on it later in the evening so I would have been able to complete had I
started it soon enough.
