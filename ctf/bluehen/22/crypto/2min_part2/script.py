#!/usr/bin/env python3

import random
import hashlib
import sys

def computeHash(word1, word2):
	target = hashlib.sha256(b"%s %s" % (word1, word2)).hexdigest()
	return target

f=open("dictionary.txt","rb")
lngstr=f.read()
f.close()
words=lngstr.split(b"\n")[:-1]
assert(len(words)==187632)
word1=random.choice(words)
word2=random.choice(words)


targetHash = "53d32f9c0e84a34dc5eb4708fd63770236e5be614a3e099cef83433b559624a6"

testHash =computeHash(b"surrounding", b"matt")

targetHash = "0037bf7c229d58a1fdb2eca0276f2bc20e2094a91c010e42a564fcc0b07a4913"

if targetHash == testHash:
	print("Test success")

for i in range(187632):
	if ((i % 100) == 0):
		print("i = {}".format(i))

	for j in range(187632):
		if (targetHash == computeHash(words[i], words[j])):
			print("Solved: {} and {}".format(words[i], words[j]))
			sys.exit(1)

