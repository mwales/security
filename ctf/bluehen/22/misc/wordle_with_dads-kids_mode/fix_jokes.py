#!/usr/bin/env python3

import sys

jokefile = open("combined_jokes.txt","r")
alljokes = jokefile.read().split("\n")
jokefile.close()

sys.stderr.write("Read in {} jokes\n".format(len(alljokes)))

sanijokelist = []

for curjoke in alljokes:
	sanijoke = ""
	for curchar in curjoke:
		if ( (curchar >= 'A') and (curchar <= 'Z') ):
			sanijoke += curchar
		if ( (curchar >= 'a') and (curchar <= 'z') ):
			sanijoke += (chr(ord(curchar) - ord('a') + ord('A')))
	
	if (len(sanijoke) > 10 ):
		print(sanijoke)
		sanijokelist.append(sanijoke)

if (len(sys.argv) >= 2):
	print("**************************************************************")
	print(" Jokes of specified length")
	print("**************************************************************")
	numletters = int(sys.argv[1])

	for curjoke in sanijokelist:
		if (numletters == len(curjoke) ):
			print(curjoke)


