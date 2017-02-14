#!/usr/bin/env python


import lzma
import sys

if (len(sys.argv) == 2):
  print "Not enough args:"
  print "Usage: lzma_decompress.py input_file outputfile"
  sys.exit(0)

data = open(sys.argv[1], 'r')
output = open(sys.argv[2], 'w')

output.write(lzma.decompress(data.read()))


