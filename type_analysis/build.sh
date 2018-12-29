#!/bin/bash

# To build the arm binary on Linux (I used Ubuntu 16.04)
# sudo apt-get install gcc-5-multilib-arm-linux-gnueabihf

mkdir bins


# Build ARM
arm-linux-gnueabi-gcc main.c -o bins/arm_main -static

# Build x86_64 / host architecutre
gcc main.c -o bins/amd64_main

# Run the different versions

./bins/amd64_main > output/amd64.txt

qemu-arm ./bins/arm_main > output/arm32.txt




