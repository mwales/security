#!/usr/bin/env python3


class baby_arx():
    def __init__(self, key):
        print("Key len = {}".format(len(key)))
        assert len(key) == 64
        self.state = list(key)

    def b(self):
        b1 = self.state[0]
        b2 = self.state[1]
        b1 = (b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff
        b2 = (b2 ^ ((b2 >> 5) | (b2 << 3))) & 0xff
        b = (b1 + b2) % 256
        self.state = self.state[1:] + [b]
        return b

    def stream(self, n):
        return bytes([self.b() for _ in range(n)])

def findNextByteToAdd(flag, desiredBytes):
	answerBytes = []

	for nextByteAdd in range(256):
		flagTry = flag.copy()
		print("Test byte to add is {} Flag Length = {}".format(nextByteAdd, len(flag)))

		flagTry = flag.copy()
		flagTry.append(nextByteAdd)
		print("Flag Try: {}".format(flagTry.hex()))

		# Make it long enough
		flagTryWithPad = flagTry.copy()
		while (len(flagTryWithPad) < 64):
			flagTryWithPad.append(0)

		#print("Attempt baby arx")

		cipher = baby_arx(flagTryWithPad)
		out = cipher.stream(64)

		# Did the first bytes match?
		matchSuccess = True
		for i in range(len(flag)):
			if out[i] != desiredBytes[i]:
				matchSuccess = False
				break

		if (matchSuccess):
			print("Match success! " + out.hex())
			answerBytes.append(nextByteAdd)
			break

	print("Num Answers = {}, answer bytes = {}".format(len(answerBytes), answerBytes))

	if (len(answerBytes) == 1):
		retVal = flag.copy()
		retVal.append(answerBytes[0])
		return retVal
	else:
		return None


# Stuff part of the original challenge / how it opened the flag file
#FLAG = open('./flag.txt', 'rb').read().strip()
#cipher = baby_arx(FLAG)
#out = cipher.stream(64).hex()
#print(out)

# The comment line at the end is the desired output they wanted original script to generate
desiredOutStr = "cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b"

desiredOutBytes = bytes.fromhex(desiredOutStr)

print (desiredOutBytes.hex())

# If you assume that the flag file starts out DUCTF...
flag = bytearray()
flag.append(0x44) # D
flag.append(0x55) # U
flag.append(0x43) # C
flag.append(0x54) # T
flag.append(0x46) # F

# And then try to determine the rest of flag by trying all 256 possible values for the next byte, one at a time.
# If the value guessed generates the next desired byte, keep it and guess the next byte

while (len(flag) < 64):
	print("Adding another byte to the flag")
	flagTry = flag.copy()

	flagExp = findNextByteToAdd(flagTry, desiredOutBytes)
	print("flagExp = {}".format(flagExp))

	if (flagExp == None):
		print("Reached a dead end")
		break
	else:
		flag = flagExp

