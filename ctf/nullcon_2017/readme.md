# NullCon 2017

Didn't have much time this weekend to play, but I looked at a few of the challenges.

## Programming 1

This was a series of RGB values in plain ASCII file.  I know from past experience that Qt has a
pretty good image library, so I figured I would use it to convert the file into an image.

I had to first figure out the size of the image.  Fortunately, after creating a program to read
in all the pixels, I could determine how many pixels there were.  I found an online website that
would factor the number for me, and it only had 2 unique factors.

> 929 x 569 = 528601

My [application](programming1/main.cpp) reads the data points from stdin, and then write an 
output.png file.  You can then open the PNG in an image viewer and see the flag:

![Flag Image](programming1/output.png "Flag")

# Programming 3

This challenge featured a binary file that that the file application tells you is a compressed
archive.  You go ahead and decompress it, and you find another compressed binary archive nested
within.

You quickly realize that this trend is going to end soon.  You have to create a script that will
decompress LZMA, tar, xz, gzip, bzip2, NuFile (some strange Apple format that I had never heard of
before), lzip, zpaq, zoo, 7zip, arj, and zip.

Most of the formats have archive manager packages you can install with the Ubuntu package manager.
(Thanks for making me install such a large quantity of dumb packages for this challenge!)  A few
were not in Ubuntu repos, and I had to find a github repo with source and compiled them.

I didn't actually complete this challenge successfully.  I finally got to a plain ASCII file, that
contained some text I thought was the flag, but it was garbage.  I think based on other writeups 
that this was generally the correct solution, I just screwed up something along the way.

But in the interest of never writing a script like this again, i will post my shame here on github.

I also realized later that there is a standalone lzma archive utility, but I ended up making a
short python script to handle it for me.
