#!/usr/bin/env python3

from PIL import Image

# Open the image
img = Image.open("red.png")

# Get pixel data 
pixels = img.load()

# Get image dimensions
width, height = img.size

print(f"Image size is {width} x {height}")


# Read the RGB value of a pixel at (x, y)
x = 0  # Replace with the desired x-coordinate
y = 0   # Replace with the desired y-coordinate


flag = ""

for x in range(0,width,2):
 
	colorinfo = pixels[x, y]

	print(colorinfo)

	r,g,b,a = colorinfo

	bit0 = r & 1
	bit1 = g & 1
	bit2 = b & 1
	bit3 = a & 1

	part1 = (bit0 << 3) + (bit1 << 2) + (bit2 << 1) + (bit3)
	print(hex(part1))
	print(f"b0 = {bit0}, b1 = {bit1}, b2 = {bit2}, b3 = {bit3}")
  
	colorinfo = pixels[x+1, y]

	print(colorinfo)

	r,g,b,a = colorinfo

	bit0 = r & 1
	bit1 = g & 1
	bit2 = b & 1
	bit3 = a & 1

	part2 = (bit0 << 3) + (bit1 << 2) + (bit2 << 1) + (bit3)
	print(hex(part2))
	print(f"b0 = {bit0}, b1 = {bit1}, b2 = {bit2}, b3 = {bit3}")

	asciiCode = (part1 << 4) + part2
	print(f" asciiCode = {hex(asciiCode)} = {chr(asciiCode)}")

	flag += chr(asciiCode)

print(flag) 
