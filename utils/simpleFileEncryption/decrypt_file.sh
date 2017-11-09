#!/bin/bash

if [ $# != "2" ]; then
  echo "Usage $0 input.enc output.txt"
  exit 1
fi

openssl enc -d -aes-256-cbc -in $1 -out $2

if [ $? != 0 ]; then
  echo "Error"
else
  echo "Done"
fi


