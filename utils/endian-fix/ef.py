#!/usr/bin/env python3

import sys

def main(args):
	if (len(args) != 4):
		print(f"Usage: {args[0]} numbytesperword infile outfile")
		return

	numBytesPerWord = int(args[1])
	filename = args[2]
	outName = args[3]

	f = open(filename, "rb")
	fileData = f.read()
	f.close()

	outFile = open(outName, "wb")

	for i in range(0, len(fileData), 4):
		bytesToSwap = numBytesPerWord
		if (len(fileData) - i < bytesToSwap):
			bytesToSwap = len(fileData) - i
		for j in range(0, bytesToSwap):
			curIndex = i
			curIndex += bytesToSwap - j - 1
			outFile.write(fileData[curIndex:curIndex+1])
	
	outFile.close()


if __name__ == "__main__":
	main(sys.argv)
