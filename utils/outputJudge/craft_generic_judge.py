#!/usr/bin/env python3

'''
Pass this the script the desired output from a challenge.  Run this script
in a directoy that has flag.txt.  The script will hash the desired user
output into 2 hashes.  One of the hashes we use later in a judge script to
verify the output is correct, the other hash is used to encrypt the flag.
This script then creates a judge.py script that the user can run to check
their output, if their output is correct, they get the decrypted flag.
'''

import sys, hashlib, binascii, base64

def debug(msg):
	if(True):
		sys.stderr.write(msg + "\n")

# This is the judge_template.py base64 encoded so this script can be run anywhere
CODE_JUDGE_TEMPLATE = """
IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoKaW1wb3J0IHN5cywgaGFzaGxpYiwgYmluYXNjaWkKClZF
UklGWV9IQVNIRVMgPSAxMzM3X1ZFUklGWV9IQVNIXzEzMzcKQ0lQSEVSX0hBU0ggPSBiIjEzMzdf
Q0lQSEVSX0hBU0hfMTMzNyIKCmRlZiBkZWJ1Zyhtc2c6c3RyKToKCWlmKEZhbHNlKToKCQlzeXMu
c3RkZXJyLndyaXRlKG1zZyArICJcbiIpCgpkZWYgY2xlYW5MaW5lRW5kaW5ncyh0ZXh0OiBzdHIp
IC0+IGxpc3Rbc3RyXToKCWNsZWFuT3V0cHV0ID0gW10KCXRleHRMaW5lcyA9IHRleHQuc3BsaXQo
IlxuIikKCWZvciBzaW5nbGVMaW5lIGluIHRleHRMaW5lczoKCQljbGVhbk91dHB1dC5hcHBlbmQo
c2luZ2xlTGluZS5zdHJpcCgpKQoJcmV0dXJuIGNsZWFuT3V0cHV0CgpkZWYgY3JlYXRlVmVyaWZ5
SGFzaGVzKHRleHQ6IGxpc3Rbc3RyXSkgLT4gbGlzdFtieXRlc106CglyZXRWYWwgPSBbXQoJZm9y
IHNpbmdsZUxpbmUgaW4gdGV4dDoKCgkJdmVyaWZ5SGFzaCA9IGhhc2hsaWIuc2hhMjU2KCkKCQl2
ZXJpZnlIYXNoLnVwZGF0ZShzaW5nbGVMaW5lLmVuY29kZSgidXRmLTgiKSkKCQlyZXRWYWwuYXBw
ZW5kKHZlcmlmeUhhc2guZGlnZXN0KCkpCgoJcmV0dXJuIHJldFZhbAoKCmRlZiBjcmVhdGVTaGE1
MTJIYXNoKHRleHQgOiBsaXN0W3N0cl0pIC0+IGJ5dGVzOgoJZ2lhbnRTdHJpbmcgPSAiXG4iLmpv
aW4odGV4dCkKCQkKCWtleUhhc2ggPSBoYXNobGliLnNoYTUxMigpCglrZXlIYXNoLnVwZGF0ZShn
aWFudFN0cmluZy5lbmNvZGUoInV0Zi04IikpCgoJcmV0dXJuIGtleUhhc2guZGlnZXN0KCkKCmRl
ZiB4b3JCeXRlQXJyYXkoYSwgYik6CgkjIFRoaXMgYml0IG9mIGNsZXZlcm5lc3MgZnJvbSBzdGFj
a292ZXJmbG93IHBvc3QKCSMgaHR0cHM6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvNTI4
NTEwMjMvcHl0aG9uLTMteG9yLWJ5dGVhcnJheXMKCXJldFZhbCA9IChieXRlcyh4IF4geSBmb3Ig
KHgseSkgaW4gemlwKGEsYikpKQoJcmV0dXJuIHJldFZhbAoKZGVmIG1haW4oYXJncyk6CglyYXdP
dXRwdXQgPSBzeXMuc3RkaW4ucmVhZCgpLnN0cmlwKCkKCgljbGVhbk91dHB1dCA9IGNsZWFuTGlu
ZUVuZGluZ3MocmF3T3V0cHV0KQoJCgl2ZXJpZnlIYXNoZXMgPSBjcmVhdGVWZXJpZnlIYXNoZXMo
Y2xlYW5PdXRwdXQpCglrZXlIYXNoID0gY3JlYXRlU2hhNTEySGFzaChjbGVhbk91dHB1dCkKCglm
b3IgKGksIGwpIGluIGVudW1lcmF0ZShjbGVhbk91dHB1dCk6CgkJaWYgKGkgPj0gbGVuKFZFUklG
WV9IQVNIRVMpICk6CgkJCXByaW50KCJZb3UgaGF2ZSBleHRyYSBsaW5lcyBvZiBvdXRwdXQhIikK
CQkJcmV0dXJuCgoJCWlmIChWRVJJRllfSEFTSEVTW2ldICE9IGJpbmFzY2lpLmhleGxpZnkodmVy
aWZ5SGFzaGVzW2ldKSk6CgkJCXByaW50KCJPdXRwdXQgaW5jb3JyZWN0IikKCQkJcHJpbnQoZiJM
aW5lIHtpKzF9OiB7bH0iKQoJCQlyZXR1cm4KCQkJCglpZiAobGVuKGNsZWFuT3V0cHV0KSAhPSBs
ZW4oVkVSSUZZX0hBU0hFUykpOgoJCXByaW50KCJNaXNzaW5nIGxpbmVzIG9mIG91dHB1dCIpCgkJ
cmV0dXJuCgoJIyBFbmNyeXB0IHRoZSBmbGFnCglwbGFpblRleHQgPSB4b3JCeXRlQXJyYXkoa2V5
SGFzaCwgYmluYXNjaWkudW5oZXhsaWZ5KENJUEhFUl9IQVNIKSkKCWRlYnVnKCJQbGFpbnRleHQg
ICAgPSB7fSIuZm9ybWF0KGJpbmFzY2lpLmhleGxpZnkocGxhaW5UZXh0KSkpCgoJcHJpbnQoIkNv
bmdyYXRzISIpCglwcmludChwbGFpblRleHQuZGVjb2RlKCJ1dGYtOCIpKQoKaWYgX19uYW1lX18g
PT0gIl9fbWFpbl9fIjoKCW1haW4oc3lzLmFyZ3YpCg==
"""

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
		
		# debug(f"  Line with hash {verifyHash.digest()} is {singleLine}")

	return retVal

def createSha512Hash(text : list[str]) -> bytes:
	giantString = "\n".join(text)
		
	keyHash = hashlib.sha512()
	keyHash.update(giantString.encode("utf-8"))

	return keyHash.digest()
	
def convertHashListIntoHexList(hashList: list[bytes]) -> str:
	retVal = '[   b"'
	hashHexList = []
	for h in hashList:
		hashHexList.append(binascii.hexlify(h).decode("utf-8"))
	
	retVal += '", \n   b"'.join(hashHexList)
	retVal += '" ]\n'
	return retVal

def xorByteArray(a, b):
	# This bit of cleverness from stackoverflow post
	# https://stackoverflow.com/questions/52851023/python-3-xor-bytearrays
	retVal = (bytes(x ^ y for (x,y) in zip(a,b)))
	return retVal

def getJudgeTemplate():
	jtraw = base64.b64decode(CODE_JUDGE_TEMPLATE)
	return jtraw.decode("utf-8")

def main(args):
	rawOutput = sys.stdin.read().strip()

	cleanOutput = cleanLineEndings(rawOutput)
	
	verifyHashes = createVerifyHashes(cleanOutput)
	
	
	keyHash = createSha512Hash(cleanOutput)

	debug("Verify Hash  = {}".format(convertHashListIntoHexList(verifyHashes)))
	debug("Key Hash     = {}".format(binascii.hexlify(keyHash)))
	debug("Key Hash Len = {}".format(len(keyHash)))
	
	flagFile = open("flag.txt","r")
	flag = flagFile.read().strip()
	flagFile.close()

	if (len(flag) > len(keyHash)):
		sys.stderr.write("Flag is too long, must be less than {} bytes".format(len(keyHash)))
		return

	while(len(flag) < len(keyHash)):
		# Pad the end of the flag to make it match the key hash len
		flag += " "
	debug("Flag PT      = {}".format(binascii.hexlify(flag.encode("utf-8"))))
	
	# Encrypt the flag
	cipherText = xorByteArray(keyHash, flag.encode("utf-8") )
	debug("Ciphertext   = {}".format(binascii.hexlify(cipherText)))
	
	judgeText = getJudgeTemplate()
	
	cipherTextHex = binascii.hexlify(cipherText).decode("utf-8")
	debug(cipherTextHex)


	judgeText = judgeText.replace("1337_VERIFY_HASH_1337", convertHashListIntoHexList(verifyHashes))
	judgeText = judgeText.replace("1337_CIPHER_HASH_1337", cipherTextHex)

	print(judgeText)

	sys.stderr.write("Judge Script Output Complete\n")



if __name__ == "__main__":
	main(sys.argv)
