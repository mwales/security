# Notes about using Unicorn

## Build

git clone https://github.com/unicorn-engine/unicorn
cd unicorn
./make.sh linux32
sudo ./make.sh install

## Compiling Unicorn stuff

There example had a make file, but for really simple stuff:

Compiling C that uses unicorn (to emulate ARM32 on AMD64):

gcc -pthread sample_armeb.c -m32 -lunicorn

## Unicorn projects

### First emulation - 3DS FTP Program

Emulated some code that dealt with string manipulation on ARM from ftpd.

The ftpd was originally built for 3DS, and adapted for android drone.

* It has ARM thumb emulation
* Patch out calls to strcpy, strstr, and realpath with NOPs, then execute
  native equivalent code
* Macro for checking errors for calls to Unicorn API
* Dumping ARM registers, unicorn memory types
* Loading binary files into useable pages for Unicorn
* Hex dumping
* Instruction tracing

What it still needs / could be improved

* Dynamic containers for stuff instead of hardcoded arrays (patching system)
* ARM mode patching support
* No memory is ever freed, leaks everywhere
* C++.  Help with memory leaks, use STL containers
* Script dumping memory from Binary Ninja / IDA Pro
* Better way to feed data (than update string and recompile) for fuzzing and what not

