#!/usr/bin/env python

from pwn import *

def hash_string(src):
   retVal = 0
   for singleChar in src:
      retVal += ord(singleChar) 

   return retVal % 16

   
t = remote('shell2017.picoctf.com', 63004)

# Level 1
binary = t.recvline_contains('UNLOCK NEXT LEVEL')

log.info('Binary : ' + binary)

partsOfLastString = binary.split(' ')
justBinary = partsOfLastString[partsOfLastString.index('of')+1]

log.info('Parsed: ' + justBinary)

intForm = hex(int(justBinary, 2))

log.info('Normal number: ' + intForm)

asciiForm = unhex(intForm[2:])

log.info('Ascii form: ' + asciiForm)

t.sendline(asciiForm)

# Level 2
level2 = t.recvline_contains('UNLOCK NEXT LEVEL')

t.sendline(intForm[2:])

t.recvline_contains("Now decimal")

t.sendline(str(int(justBinary, 2)))

# Level 3
level3 = t.recvline_contains('UNLOCK NEXT LEVEL')

level3Parts = level3.split(' ')

hashVal = level3Parts[level3Parts.index('after') - 1]

log.info("Whole Line Lv3: " + level3)
log.info("Hash: " + hashVal)

starterString = "farts!"

while(hash_string(starterString) != int(hashVal)):
  starterString = starterString[:-1] + chr(ord(starterString[-1:]) + 1)

log.info("Solution = " + starterString)
log.info("Hash = " + str(hash_string(starterString)))

t.sendline(starterString)

# Level 4 - Do the MD5 hash challenge interactively (look it up online) 
t.interactive()



