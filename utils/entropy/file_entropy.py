#!/usr/bin/env python

# This is code that was posted on code.adtivestate.com (and blogged about by kenneth G. Hartman
# on www.kennethghartman.com/calculate-file-entropy/).  A Shannon entropy value of 8 would indicate
# highest possible entropy of a file

# file_entropy.py
#
# Shannon Entropy of a file
# = minimum average number of bits per character
# required for encoding (compressing) the file
#
# So the theoretical limit (in bytes) for data compression:
# Shannon Entropy of the file * file size (in bytes) / 8
# (Assuming the file is a string of byte-size (UTF-8?) characters
# because if not then the Shannon Entropy value would be different.)
# FB - 201011291
import sys
import math
if len(sys.argv) != 2:
    print "Usage: file_entropy.py [path]filename"
    sys.exit()

# read the whole file into a byte array
f = open(sys.argv[1], "rb")
byteArr = map(ord, f.read())
f.close()
fileSize = len(byteArr)
print 'File size in bytes:'
print fileSize
print

# calculate the frequency of each byte value in the file
freqList = []
for b in range(256):
    ctr = 0
    for byte in byteArr:
        if byte == b:
            ctr += 1
    freqList.append(float(ctr) / fileSize)
# print 'Frequencies of each byte-character:'
# print freqList
# print

# Shannon entropy
ent = 0.0
for freq in freqList:
    if freq > 0:
        ent = ent + freq * math.log(freq, 2)
ent = -ent
print 'Shannon entropy (min bits per byte-character):'
print ent
print
print 'Min possible file size assuming max theoretical compression efficiency:'
print (ent * fileSize), 'in bits'
print (ent * fileSize) / 8, 'in bytes'


