#!/usr/bin/env python

import subprocess
import os
import sys
import time

if len(sys.argv) != 2:
   print "Usage is scriptName outputFromReverseBox"
   sys.exit()

cipherTable = ""

# You can't just use all printable ASCII, because a lot of non-alphanumeric characters will piss of the shell.
#for printableChar in range(20,127):

for printableChar in range(48,57) + range(65,90) + range(97,122) + [123, 125, 45, 95]:
   cipherTable += chr(printableChar)

print "ASCII Table =" + cipherTable

for cipherIndex in range(1, 256):
   print "Cipher Index", cipherIndex

   patchCode = "b8" + format(cipherIndex, '02x') + "0000008945f4"

   #print ("Patch code = " + patchCode)

   print("Patching: ./patch32 reverse_box.hacked 0x80485ac 0xe " + patchCode)
   patchProcessOutput = subprocess.Popen("./patch32 reverse_box.hacked 0x80485ac 0xe " +  patchCode, shell=True, stdout=subprocess.PIPE).stdout.read()
   
   #print "Patch process output:  " + patchProcessOutput


   decipherTable = subprocess.Popen("./reverse_box.hacked \"" + cipherTable + "\"", shell=True, stdout=subprocess.PIPE).stdout.read()

   print decipherTable

   # Now need to create a map of plaintext to ciphertext
   reversingMap = { }
   for i in range(0,len(cipherTable)):
      hexCode = decipherTable[i*2:i*2+2]
      reversingMap[hexCode] = cipherTable[i]
      #sys.stdout.write(" " + hexCode + "=" + cipherTable[i])
   #sys.stdout.write("\n")

   keyCopy = sys.argv[1]
   
   sys.stdout.write("Plaintext:             ")
   for singlePt in cipherTable:
      sys.stdout.write(singlePt + " ")
   sys.stdout.write("\n")
   sys.stdout.write("Key Ciphercode         " + decipherTable + "\n")
   sys.stdout.write("Cipher Text to decode: " + sys.argv[1] + "\n")
   
   sys.stdout.write("Input to keygen:       ")
   while(len(keyCopy) >= 2):
      lookMeUp = keyCopy[0:2]
      if lookMeUp in reversingMap:
         sys.stdout.write(reversingMap[lookMeUp])
      else:
         sys.stdout.write(" ")

      # Move onto the next byte of user param
      keyCopy = keyCopy[2:]

   sys.stdout.write("\n")


