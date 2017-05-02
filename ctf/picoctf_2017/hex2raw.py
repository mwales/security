#!/usr/bin/env python

from pwn import *

a = process('/problems/33432c6de9329bca3a3ff26e5538d8f2/hex2raw')

throwaway = a.recvline()
convertme = a.recvline()
a.recvline_endswith(':')

log.info("Throwaway = " + throwaway)
log.info("Convert Me = " + convertme)

a.sendline(unhex(convertme.strip()))

flag = a.recvall()

log.info("Flag = " + flag)

