#!/usr/bin/python

import sys

if (len(sys.argv) != 2):
	print("Give us Badge Num!");
	sys.exit(1)


badgenum = int(sys.argv[1])

alice = str(badgenum ^ 2784639871)
bob = str(badgenum ^ 0xe35c2742)
dan = str(badgenum ^ 0x87e35d46)
eve = str(badgenum ^ 0x5acd14f9)
trevor = str(badgenum ^ 0xabde1fcf)
carol = str(badgenum ^ 0xbec5ca0f)

# The number the user enters gets rotated 1 character
print("alice  = {}{}".format(alice[-1], alice[0:-1]))
print("bob    = {}{}".format(bob[-1], bob[0:-1]))
print("dan    = {}{}".format(dan[-1], dan[0:-1]))
print("carol  = {}{}".format(carol[-1], carol[0:-1]))
print("eve    = {}{}".format(eve[-1], eve[0:-1]))
print("trevor = {}{}".format(trevor[-1], trevor[0:-1]))


