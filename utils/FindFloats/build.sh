#!/bin/bash

rm -rf build
mkdir build
cd build
qmake ../FindFloats.pro
make -j4


