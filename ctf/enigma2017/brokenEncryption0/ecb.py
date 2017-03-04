#!/usr/bin/python -u
from Crypto.Cipher import AES

# This was the problem file given by the challenge, not my source

flag = open("flag", "r").read().strip()
key = open('enc_key', 'r').read().strip().decode('hex')

welcome = """
************ MI6 Secure Encryption Service ************
                  [We're super secure]
       ________   ________    _________  ____________;_
      - ______ \ - ______ \ / _____   //.  .  ._______/ 
     / /     / // /     / //_/     / // ___   /
    / /     / // /     / /       .-'//_/|_/,-'
   / /     / // /     / /     .-'.-'
  / /     / // /     / /     / /
 / /     / // /     / /     / /
/ /_____/ // /_____/ /     / /
\________- \________-     /_/

"""

def pad(m):
  m = m + '1'
  while len(m) % 16 != 0:
    m = m + '0'
  return m

def encrypt():
  cipher = AES.new(key,AES.MODE_ECB)

  m = raw_input("Agent number: ")
  m = "agent " + m + " wants to see " + flag

  return cipher.encrypt(pad(m)).encode("hex")

print welcome
print encrypt()
