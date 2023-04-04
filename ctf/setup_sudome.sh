#!/bin/bash

user=$(whoami)
if [ "$user" != "root" ]; then
	echo "Need to run as root user"
	exit 1
fi

echo "Getting apt ready"


apt update
apt upgrade -y

# Pwn tools requires: python3-pip python3-dev libssl-dev libffi-dev build-essential

apt-get install -y vim tmux guake build-essential python3-pip python3-dev libssl-dev vim geany qtbase5-dev-tools qtbase5-doc \
   gdb-multiarch gdbserver gdb qemu qemu-system-arm qemu-utils docker.io nmap openssh-server wireshark picocom putty \
   socat curl binutils-multiarch binwalk ghex kpartx steghide pdftk imagemagick silversearcher-ag open-vm-tools \
   openjdk-18-jdk libffi-dev

