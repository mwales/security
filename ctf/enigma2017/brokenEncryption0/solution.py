#!/usr/bin/env python

import sys
import socket

# Part of padding oracle initial proof-of-concept test
#agent_name_padding_only = ' ' * 10 + '1' + '0' * 15
#sys.stdout.write(agent_name_padding_only)

# Pad the front of the agent name with garbage because the first block of data is useless for us
# since we can't control all of the plaintext
agentNamePrefix = 'a' * 10

numBytesAfterName = len(' wants to see ')

# You are able to figure out the flag length by creating longer user names and then seeing when the
# ciphertext grows an extra block
flagLength = 49

def getFlag(knownFlag):

  print("Flag bytes known so far=" + knownFlag)

  hostname = 'enigma2017.hackcenter.com'
  portNum = 32335

  print("Connecting to server {}:{}".format(hostname, portNum))

  s = socket.create_connection( (hostname, portNum) )

  garbage_data = s.recv(4096)

  # Figure out what to send to the oracle
  knownFlagBytes=len(knownFlag)
  blocksAnalyzingAtEnd = ((knownFlagBytes + 1) // 16) + 1
  paddingBytes = 16 - knownFlagBytes + 1 % 16
  print("Num Blocks Analyzing = {}".format(blocksAnalyzingAtEnd))
  print("Padding 0 bytes = {}".format(paddingBytes))

  messageEnding = knownFlag + '1' + '0' * paddingBytes
  print("Message ending=" + messageEnding)

  # Get the agent name on a block boundary
  msg = agentNamePrefix

  for guessChar in range(0x20,0x7f):
    endOfMessageGuess = chr(guessChar) + messageEnding
    msg += endOfMessageGuess[0:16]

  flagBytesNotGuessing = flagLength - knownFlagBytes - 1
  print("Num flag bytes not guessing = {}".format(flagBytesNotGuessing))

  numFillerBytes = 16 - ((flagBytesNotGuessing + numBytesAfterName) % 16)
  print("Number of filler bytes after agent name = {}".format(numFillerBytes))

  msg += '-' * numFillerBytes

  print("Message (length = {}):".format(len(msg)))
  print(msg)

  s.send(msg + '\n')

  response = ''
  while(True):
    response += s.recv(4096)

    if (response.rfind('\n') > 10):
      break 


  print("Response:\n" + response.strip())

  ctOnly = response.strip()[len("Agent number: "):]

  print("CtOnly (Length={} bytes)\n={}".format(len(ctOnly)/2, ctOnly))

  if ( (len(ctOnly) % 32) != 0 ):
    print("Cipher text length invalid, not a 16-byte boundary!!!")
    sys.exit(1)

  actualBlockData = ""
  while(blocksAnalyzingAtEnd != 0):
    actualBlockData = ctOnly[-32:]
    ctOnly = ctOnly[:-32]
    blocksAnalyzingAtEnd -= 1

  print("Actual block of data at end to match against:")
  print(actualBlockData)

  # Throw away garbage block at beginning
  ctOnly = ctOnly[32:]

  for guessChar in range(0x20, 0x7f):
    guessBlock = ctOnly[:32]
    ctOnly = ctOnly[32:]

    if (guessBlock == actualBlockData):
      print("We found the guessed block!!")
      print("Flag Known={}{}".format(chr(guessChar), knownFlag))
      
      # Recursively call self
      computedFlag = chr(guessChar) + knownFlag;
      if (len(computedFlag) == flagLength):
        print("Flag found!!!!  Done!")
        
      else:
        print("Find the previous part of flag now")
        getFlag(chr(guessChar) + knownFlag)
        
      sys.exit(0)

    
if __name__ == '__main__':
  knownFlag = ''
  if (len(sys.argv) == 2):
    knownFlag = sys.argv[1]
    
  getFlag(knownFlag)
  

