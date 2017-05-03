#!/usr/bin/env python

# I later realized that openssl looks like it can take base64 data already with corresponding
# command line switch enabled

from Crypto.Cipher import AES
from pwn import *

b64Ct = 'I300ryGVTXJVT803Sdt/KcOGlyPStZkeIHKapRjzwWf9+p7fIWkBnCWu/IWls+5S'
b64Key = 'iyq1bFDkirtGqiFz7OVi4A=='

ct = base64.b64decode(b64Ct)
key = base64.b64decode(b64Key)

log.info("Key length = " + str(len(key) * 8))

log.info("Key = " + enhex(key))

# aes-128-ecb

ctFile = open("ct.bin", 'w')
ctFile.write(ct)
ctFile.close()

subprocess.call(['openssl', 'enc', '-aes-128-ecb', '-in', 'ct.bin', '-out', 'pt.bin', '-d', '-K', enhex(key), '-nopad'])

ptFile = open("pt.bin", 'r')
flag = ptFile.read()
ptFile.close()

log.info("Flag: " + flag)

os.remove('pt.bin')
os.remove('ct.bin')

