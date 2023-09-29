#!/usr/bin/env python3

from pwn import *

flag = "vsctf{w34k_4nt1_d3bugg3rs_4r3_n0_m4tch_f0r_th3"
known_flag_bytes = len(flag)
while(len(flag) < 53):
	flag += "a"

def testFlag(flag):
	print("Testing flag {}".format(flag))

	sh = process("./inject.sh")

	et = sh.recvline()
	et = sh.recvline()
	et = sh.recvline()
	et = sh.recvline()
	et = sh.recvline()
	print("early text = {}".format(et))
	sh.send(flag + b"\n")
	d = sh.recvline()
	d = sh.recvline()
	parts = d.strip().decode("utf-8").split(" ")
	if (len(parts) != 6):
		print(d)
		sh.shutdown()
		sh.wait()
		return 0
	else:
		sh.shutdown()
		sh.wait()
		return int(parts[5])


for i in range(known_flag_bytes,len(flag)):
	# test 0x21 to 0x7e
	print("*** Oracle at position %d ***", i)
	for curChar in range(0x21, 0x7f):
		curflag = flag[:i] + chr(curChar) + flag[i+1:]
		numRight = testFlag(curflag.encode("utf-8"))
		if (numRight == (i+1)):
			flag = curflag
			break

print("Done")
