#!/bin/bash

rm -rf build
mkdir build
cd build
qmake ../ReverseCrc.pro
make -j4


