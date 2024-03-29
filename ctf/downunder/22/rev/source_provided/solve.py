#!/usr/bin/env python3

# The original program had a 0x32 byte buffer of data.  This is that data in a python array.
# I originally tried to reverse the manipulations, but it didn't work, not sure why.  I was
# successful justing guessing all 256 bytes for each byte and see which value matches after
# performing all manipulations the assembly did.

# The data copied from the assembly.  
data = [ 0xc4, 0xda, 0xc5, 0xdb, 0xce, 0x80, 0xf8, 0x3e,
         0x82, 0xe8, 0xf7, 0x82, 0xef, 0xc0, 0xf3, 0x86,
         0x89, 0xf0, 0xc7, 0xf9, 0xf7, 0x92, 0xca, 0x8c,
         0xfb, 0xfc, 0xff, 0x89, 0xff, 0x93, 0xd1, 0xd7,
         0x84, 0x80, 0x87, 0x9a, 0x9b, 0xd8, 0x97, 0x89,
         0x94, 0xa6, 0x89, 0x9d, 0xdd, 0x94, 0x9a, 0xa7,
         0xf3, 0xb2 ]

s = ""
for i in range(len(data)):
	# This "reverse" algo failed for me
	#curByte = (data[i] ^ 0x42 - 0x42 + i) & 0xff
	#print("{}      data={}       data-xor={}       data-minus-plux={}".format(i, data[i], data[i] ^ 0x42, hex(curByte)))
	#s += chr(curByte)

	# This is the technique that did work.  Try all 256 values, see which ones work
	for x in range(255):
		calc = ( (x + i + 0x42) ^ 0x42) & 0xff
		if (calc == data[i]):
			#print("     at i={}   x={}     data={}".format(i, hex(x), hex(calc)))
			s += chr(x)

# Print the flag
print(s)
