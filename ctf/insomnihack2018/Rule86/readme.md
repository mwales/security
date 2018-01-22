# Partial Writeup 

I didn't get to finish this problem

## Files given to you

* hint.gif.enc
* rule86.txt (511 bytes)
* rule86.txt.enc (512 bytes)
* super_cipher.py.enc (768 bytes)

## CTF text / problem text:

Kevin is working on a new synchronous stream cipher, but he has been re-using his key.

## Strategy

So when I think about a stream cipher, I think about AES encryption in CTR mode.  In that mode AES
is basically generating a pseudo-random stream of bytes that are initialized with the AES key and
nonce.  This basically makes it a clever one time pad, which is why you can never reuse a nonce in
this mode.

So knowing that, and reading the problem statement, I'm immediately thinking that this is a
one time pad type of problem.  And since they gave me a plaintext and ciphertext, I should be able
to extract the key used.  I use my xor program to xor rule86.txt and rule86.txt.enc together:

    ./xor rule86.txt rule86.txt.enc key.out
    Files are not the same length, output will be truncated
    Bytes read so far from buf1 511
    Bytes read so far from buf2 511
    Bytes written so far from buf1 511

I could then use this key to decrypt the first 511 bytes of hint.gif and super_cipher.py

Decrypting the GIF didn't tell me much, I was able to see the magic bytes GIF89a.

Decrypting the first 511 bytes of the super_cipher.py script was a little bit more interesting.
Here is the first 511 bytes of that file (missing about 240 bytes from the end of the file):

```python
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument("key")
args = parser.parse_args()

RULE = [86 >> i & 1 for i in range(8)]
N_BYTES = 32
N = 8 * N_BYTES

def next(x):
  x = (x & 1) << N+1 | x << 1 | x >> N-1
  y = 0
  for i in range(N):
    y |= RULE[(x >> i) & 7] << i
  return y

# Bootstrap the PNRG
keystream = int.from_bytes(args.key.encode(),'little')
for i in range(N//2):
  keystream = next(keystream)

# Encrypt / decrypt stdin to stdout

```

My key takeaway from this was that it looked the ciper stream had a block that was generated from
the previous state data every 32 bytes.  So I created my own decryption tool that could then
decrypt any of these files using the first 32-bytes of the key.out file I created.  See [sc.py](sc.py)

I then used this tool to full decrypt hint.gif!

![hint.gif decrypted](hint.gif)

From this I realize that the flag is actually the initial state word given to the super_cipher.py
program.  The state is advanced once before I was able to capture it using my xor tool.  I think
to derive the key at this point I would use z3, but I've haven't completed those steps yet.

