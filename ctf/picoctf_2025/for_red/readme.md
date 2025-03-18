Was playing around with bucket fill with threshold 0 in gimp, noticed that
there were distinct vertical columns of the same color.

Then used python / PIL to analyze the color of each pixel in the top row.
The colorinfo reported for each pixel was a r,g,b,a, but the only bits that
ever changed were the low bits.

Just wrote a script to take all the low bits for two neighboring pixels and
derived an ASCII code.  That created a long base64 string which I could
decode into the flag.
