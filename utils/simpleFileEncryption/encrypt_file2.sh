#!/bin/bash

if [ $# != "2" ]; then
  echo "Usage $0 mydata.txt mydata.enc2"
  echo "  Uses SHA-512 hashing with salt 500,000 times"
  echo "  Requires recent versions of OpenSSL"
  exit 1
fi

# Add the -p option to the end of this see exact key and IV used
openssl enc -md sha512 -aes-256-cbc -salt -in $1 -out $2 -pbkdf2 -iter 500000

if [ $? != 0 ]; then
  echo "Error"
else
	echo "Done. You will need recent version of OpenSSL (Ubuntu 18.04 with updates) to decrypt"
fi


