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
AES 256 Key Pt 2 = AES-128-key + md5(AES-128-key + password + salt)

AES 256 Key = AES-128-key + AES-256-Key-Pt2

IV = md5(AES-256-key-pt2 + password + salt)

# Example

```
hexdump -C plaintext.txt
00000000  54 68 69 73 20 69 73 20  61 20 74 65 73 74 0a     |This is a test.|
```

Adding the -p option to the OpenSSL encryption call, using the password "password":

```
sh encrypt_file.sh plaintext.txt ciphertext.bin
enter aes-256-cbc encryption password:
Verifying - enter aes-256-cbc encryption password:
salt=74BD53FC5A7AECC3
key=03726BD815926FC02189FC16BCB7E7B50F4C44E81AB451B2F167118BFC379CD1
iv =3D478710816C9AB167E61C2F2C987E61
Done
```

Resulting ciphertext:

```
00000000  53 61 6c 74 65 64 5f 5f  74 bd 53 fc 5a 7a ec c3  |Salted__t.S.Zz..|
00000010  cf 22 05 89 46 ab 22 12  03 aa 82 1a e4 4c a0 06  |."..F."......L..|
00000020
```

AES 128 Key

```
# md5( pass + salt ) = aes128key
echo "70 61 73 73 77 6f 72 64 74BD53FC5A7AECC3" | ../hex2bin/a.out - | md5sum

03726bd815926fc02189fc16bcb7e7b5
```

AES 256 Key

```
# md5( aes128key + pass + salt ) = aes256 key pt2
echo "03726bd815926fc02189fc16bcb7e7b5 70 61 73 73 77 6f 72 64 74BD53FC5A7AECC3" | ../hex2bin/a.out - | md5sum

0f4c44e81ab451b2f167118bfc379cd1  -
```

IV

```
# md5( aes256key-pt2 + pass + salt) = iv
echo "0f4c44e81ab451b2f167118bfc379cd1 70 61 73 73 77 6f 72 64 74BD53FC5A7AECC3" | ../hex2bin/a.out - | md5sum

3d478710816c9ab167e61c2f2c987e61  -
```





