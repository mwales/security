# CTF VM Setup

* Download latest LTS Ubuntu Mate
* Create Ubuntu VM (30GB partition)
* Wait for the installation to complete
* Install core tools

```
sudo apt-get install vim git tmux guake openssh-server
```

* Copy of ~/.ssh/id_rsa and ~/.ssh/id_rsa.pub from old system
* Checkout the git repo with scripts

```
mkdir checkouts
cd checkouts
git clone git@github.com:mwales/security.git
```

* Now run the CTF setup scripts in there
* setup_sudome.sh
* setup.sh
* Install some tools that aren't in packages
  * Binary Ninja
  * Ghidra
  * IDA Pro
  * Visual Studio Code
* close / vm reboot

