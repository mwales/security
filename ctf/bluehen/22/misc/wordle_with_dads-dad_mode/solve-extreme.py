#!/usr/bin/env python3

import sys
import pexpect
import json

def solveGame(child):
	#child.expect(">")
	#firstLine = child.readline()
	#print("1st: {}".format(firstLine))

	parts = child.readline().split(b' ')
	tossline = child.readline()

	isPos = -1
	curPos = 0
	for eachpart in parts:
		if (parts[curPos] == b"is"):
			isPos = curPos
			break
		curPos += 1
	
	if (isPos == -1):
		print("cant find is, fail")
		sys.exit(1)

	

	jokelen = int(parts[isPos+1])
	print(str(jokelen))
	
	properlenlist = []
	for sanijoke in sanijokelist:
		if (len(sanijoke) == jokelen):
			properlenlist.append(sanijoke)

	firstguess = properlenlist[0]
	child.sendline(firstguess)

	echoline = child.readline()
	print("echo: {}".format(echoline))

	results = child.readline()

	print("RESULTS: {}".format(results))

	if (results.find(b'One down') != -1):
		return

	jsonpos = results.find(b"{")
	jsonend = results.find(b"}")
	jsonstr = results[jsonpos:jsonend+1].replace(b"'",b'"')
	obj = json.loads(jsonstr)
	print(obj)

# now i have a map, with 2 lists

# we guessed the first one...
	properlenlist = properlenlist[1:]
	survivorset = set()
	for possibleguess in properlenlist:
		valid = True
		print(" ")
		print("Stage 2 for {}".format(possibleguess))
		print(firstguess)
		print(possibleguess)
	
		# Have to keep the correct answeres in correct spot
		for curcorrect in obj["correct"]:
			if (possibleguess[curcorrect] != firstguess[curcorrect]):
				print("{} is no good, character at {} is incorrect".format(possibleguess, curcorrect))
				valid = False
				break
			else:
				print("{} is OK, character {} at {} is correct".format(possibleguess, possibleguess[curcorrect], curcorrect))
	
		for curpossible in obj["position"]:
			if (firstguess[curpossible] not in possibleguess):
				print("{} is no good, guess at {} is nowhere to be found".format(possibleguess, curpossible))

				valid = False
				break

			if (firstguess[curpossible] == possibleguess[curpossible]):
				print("{} is no good, guess at {} is wrong / same".format(possibleguess, curpossible))
				valid = False
				break

		if (valid):
			print("Adding {}".format(curpossible))
			survivorset.add(possibleguess)

	print("************ SURVIVORS  ***********************")
	for s in survivorset:
		print(s)

	if (len(survivorset) != 1):
		print("Invalid survivor set")
		sys.exit(1)
	
	child.sendline(survivorset.pop())

	results = child.readline()
	print(results)

	results = child.readline()
	print(results)
	
	results = child.readline()
	print(results)


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
		#print(sanijoke)
		sanijokelist.append(sanijoke)

logfile = open("log.txt", "wb")

#child = pexpect.spawn("./wordleswithdads-extreme.py")
child = pexpect.spawn("nc 0.cloud.chals.io 33282")

jokeSource = child.readline()
print("jokes are from {}".format(jokeSource))


for numGames in range(10):
	print("((((((((((((( Solving {} ))))))))))))))))".format(numGames))
	solveGame(child)

child.interact()

