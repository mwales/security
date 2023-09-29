#!/bin/bash

gcc -shared -o injector.so -fPIC injector.c
export LD_PRELOAD=./injector.so
#./x0rr3al
./x0rr3al_2_extra_close
unset LD_PRELOAD

