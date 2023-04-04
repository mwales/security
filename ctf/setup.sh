#!/bin/bash

python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools

# Setup vim
cd ~
wget https://raw.githubusercontent.com/mwales/notes/master/vimrc
mv vimrc .vimrc

# Setup gef
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit

mkdir ~/Apps
cd ~/Apps

# jdgui
wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar


