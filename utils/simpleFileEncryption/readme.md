# Overview

These are simple  scripts to run with OpenSSL to configure it to encrypt one
file using AES-256-CBC encryption.  It is configured to salt the key as well.

I don't like that the key derivation function is only 1 iteration according
to sources on the internet, I would have like many times more than that.

I've included pre-compiled copies of openssl for Windows to run with the
batch files, since OpenSSL isn't normally installed on Windows systems by
default.

You execute the command like you are going to copy a single file.  You can't
encrypt or decrypt more than 1 file at a time.  For multiple scripts you
will probably need to cook somehting  up with find command.

I keep my flash drive as FAT32 so it will easily work on Windows systems.
I use the sh command to execute the scripts even if they aren't marked as
executable

# Usage

## Linux

cd /media/username/thumbdrive
sh ./encrypt_file.sh /home/username/Desktop/dontShareDoc.txt dontShareDoc.txt.enc

To decrypt
cd /media/username/thumbdrive
sh ./decrypt_file.sh dontShareDoc.txt.enc /home/otherUser/Desktop/dontShareDoc.txt

## Windows

d:
encrypt_file.bat /home/username/Desktop/dontShareDoc.txt dontShareDoc.txt.enc

To decrypt

d:
decrypt_file.bat dontShareDoc.txt.enc /home/otherUser/Desktop/dontShareDoc.txt

# How does this work

If you add -p onto the end of the OpenSSL command, it will print out the salt,
key, and IV used for the encryption step.

OpenSSL for Ubuntu 16.04 and older uses md5 hash digest function to create the
key from the password.  Not sure what newer version were changed to, but adding
the -md md5 option to the newer versions make them compatible with the older
versions again.

AES 128 Key = md5(password + salt)
AES 256 Key = AES-128-key + md5(AES-128-key + password + salt)



