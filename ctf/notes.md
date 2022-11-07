# CTF Notes

## Github projects to have checked out already

- https://github.com/JonathanSalwan/ROPgadget
- https://github.com/openwall/john

## Applications for CTF VM

### pwntools

```
python3 -m pip install --upgraded pip
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

### Bare minimum dev tools

- tmux guake
- build-essential
- git
- python3-pip python3-dev
- libssl-dev
- vim geany
- qtbase5-dev-tools qtbase5-doc

### Reversing Tools

- Ghidra (free from NSA)
- BinaryNinja (has a free web version)
- IDA Pro (costs money, decompilers cost even more)
- binutils-multiarch
- binwalk
- ghex
- jd-gui
- kpartx

Debian / Ubuntu have a forensics-all meta-package that has a large collection of tools.

### Debugging

- gdb-multiarch gdbserver gdb
- gef

### Execution

- qemu qemu-system-arm qemu-utils
- docker.io

### Networking

- nmap
- openssh-server
- wireshark
- picocom
- putty
- socat
- curl

### Media

- imagemagick
- pdftk
- steghide

### Java Reversing

- openjdk-17-jdk
- Dex2Jar
- JD-GUI
- Enigma

### Other

- silversearcher-ag
- Visual Studio Code (python debugging, markdown editor / preview)

# Docker configuration crap

You probably need to run this after installing the docker package to get the
docker user setup correctly. (Restart shell afterwards)

```
sudo usermod -aG docker ${USER}
```

Docker commands to create and manage an instance of typical CTF challenge

```
# This will build image based on Dockerfile in current directory
docker build --tag con_chal .

# Verify
docker images

# Run the image
docker run con_chal

# See if it is running?
docker ps
docker ps -a

# Run again
docker start crazyname
docker stop crazyname
docker rm crazyname

# Map a port from VM to our network
docker run -p 8080:80 --name instance_name -d con_chal
```

