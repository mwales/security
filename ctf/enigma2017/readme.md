# Enigma 2017

CTF from For All Secure hosted at hackcentral.com

# EBG13

I wrote this big application to help me solve caesar cipher like problems.

[Caesar Cipher Tool](../../utils/caesar).

But then, when talking to a friend, he suggest that he heard of a command line application called 
tr that he heard was good for using for caesar cipher tasks.  Googling that, I found this page:

[GitHubGist - casesar-cipher.sh](https://gist.github.com/IQAndreas/030b8e91a8d9a407caa6)

The last suggestion / recipe there for ROT13 solved this problem.  It actually worked better than
my utility since my utility doesn't handle case sensitivity properly.

# Two-Time Pad

Two files are encrypted using the same one-time-pad.

* pt1 ^ otp = ct1
* pt2 ^ otp = ct2

If you xor the 2 ciphertexts together, the result is 2 plaintexts xored together.

* ct1 ^ ct2 = pt1 ^ otp ^ pt2 ^ pt2
* ct1 ^ ct2 = pt1 ^ pt2

I wasn't sure how useful this would be for a bitmap, so I wrote a program to try it out.
[Xor File Utility](../../utils/xorFiles). Probably complete overkill, probably could have found
something to do this for me.

When you xor the 2 bitmaps together, it doesn't work in an image viewer.  Looking at the BMP in
010Editor reveals that there is a short header at the beginning of the file before you get to the
actualy image pixel data.  I ended up just changing the xor program to not xor anything before 
it gets to 0x36 bytes into the file.

Interestingly enough, xor-ing 2 bitmaps together leaves much of the details of the 2 source 
images intact, and the key is very easy to pick out.

# Broken Encryption 0

Message is encrypted with AES in ECB mode.  Created an attack where you can decode the message 1
byte at time.  After 49 requests of the server, the flag is decoded.


