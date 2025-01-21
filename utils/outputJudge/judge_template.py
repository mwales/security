#!/usr/bin/env python3

import sys, hashlib, binascii

VERIFY_HASHES = 1337_VERIFY_HASH_1337
CIPHER_HASH = b"1337_CIPHER_HASH_1337"

def debug(msg:str):
	if(False):
		sys.stderr.write(msg + "\n")

def cleanLineEndings(text: str) -> list[str]:
	cleanOutput = []
	textLines = text.split("\n")
	for singleLine in textLines:
		cleanOutput.append(singleLine.strip())
	return cleanOutput

def createVerifyHashes(text: list[str]) -> list[bytes]:
	retVal = []
	for singleLine in text:

		verifyHash = hashlib.sha256()
		verifyHash.update(singleLine.encode("utf-8"))
		retVal.append(verifyHash.digest())

	return retVal


def createSha512Hash(text : list[str]) -> bytes:
	giantString = "\n".join(text)
		
	keyHash = hashlib.sha512()
	keyHash.update(giantString.encode("utf-8"))

	return keyHash.digest()

def xorByteArray(a, b):
	# This bit of cleverness from stackoverflow post
	# https://stackoverflow.com/questions/52851023/python-3-xor-bytearrays
	retVal = (bytes(x ^ y for (x,y) in zip(a,b)))
	return retVal

def main(args):
	rawOutput = sys.stdin.read().strip()

	cleanOutput = cleanLineEndings(rawOutput)
	
	verifyHashes = createVerifyHashes(cleanOutput)
	keyHash = createSha512Hash(cleanOutput)

	for (i, l) in enumerate(cleanOutput):
		if (i >= len(VERIFY_HASHES) ):
			print("You have extra lines of output!")
			return

		if (VERIFY_HASHES[i] != binascii.hexlify(verifyHashes[i])):
			print("Output incorrect")
			print(f"Line {i+1}: {l}")
			return
			
	if (len(cleanOutput) != len(VERIFY_HASHES)):
		print("Missing lines of output")
		return

	# Encrypt the flag
	plainText = xorByteArray(keyHash, binascii.unhexlify(CIPHER_HASH))
	debug("Plaintext    = {}".format(binascii.hexlify(plainText)))

	print("Congrats!")
	print(plainText.decode("utf-8"))

if __name__ == "__main__":
	main(sys.argv)
