#!/usr/bin/env python3

import argparse
import sys

#parser = argparse.ArgumentParser()
#parser.add_argument("key")
#args = parser.parse_args()

RULE = [86 >> i & 1 for i in range(8)]
N_BYTES = 32
N = 8 * N_BYTES

def next(x):
  x = (x & 1) << N+1 | x << 1 | x >> N-1
  y = 0
  for i in range(N):
    y |= RULE[(x >> i) & 7] << i
  return y

# Bootstrap the PNRG

# Original program did the following to derive the keystream
#keystream = int.from_bytes(args.key.encode(),'little')
#for i in range(N//2):
#  keystream = next(keystream)

# Hypothesize that the first 256-bits of the key we computed is the keystream
# state after they initialize it in their program.  Every 256-bits of data 
# that is encrypted, redo the keystream via the next method
keyFile = open("key.out", "rb")
keyFullFile = keyFile.read()

singleKeyBlock = keyFullFile[:32]

state1 = int.from_bytes(singleKeyBlock, 'little')

print("Key =")
print(hex(state1))

stateX = (state1 & 1) << N+1 | state1 << 1 | state1 >> N-1

print("statex =")
print(hex(stateX))


print("Key Full File Length = {}".format(len(keyFullFile)))
print("RULE = {}".format(RULE))

keystream = int.from_bytes(keyFullFile[:32], 'little')

if (len(sys.argv) != 3):
  print("Usage: plaintextFileName ciphertextFileName")
  sys.exit(1)

ptFile = open(sys.argv[1], 'rb')
ctFile = open(sys.argv[2], 'wb')

doneReading = False
while not doneReading:
  ptBlock = ptFile.read(256//8)

  if (len(ptBlock) < 256//8):
    print("Last block, only {} bytes of text read".format(len(ptBlock)))
    doneReading = True
  ksb = keystream.to_bytes(256//8, 'little')
  for i in range(len(ptBlock)):
    ctFile.write((ksb[i] ^ ptBlock[i]).to_bytes(1, 'little'))
  
  #print("Done encoding a block")
  keystream = next(keystream)

ptFile.close()
ctFile.close()




