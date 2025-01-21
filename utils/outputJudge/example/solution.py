#!/usr/bin/env python3

import sys

lookup = { 0: "zero",
           1: "one",
           2: "two",
           3: "three",
           4: "four",
           5: "five",
           6: "six",
           7: "seven",
           8: "eight",
           9: "nine" }
  

while(True):
	curNumber = sys.stdin.readline().strip()

	outputWordList = []
	for curDigit in curNumber:
		value = int(curDigit)
		outputWordList.append(lookup[value])

	print(" ".join(outputWordList))

	if curNumber == "0":
		break;
