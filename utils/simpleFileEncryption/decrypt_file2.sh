#!/bin/bash

if [ $# != "2" ]; then
  echo "Usage $0 input.enc output.txt"
  exit 1
fi

openssl enc -md sha512 -d -aes-256-cbc -in $1 -out $2 -pbkdf2 -iter 500000

if [ $? != 0 ]; then
  echo "Error"
else
  echo "Done"
fi


