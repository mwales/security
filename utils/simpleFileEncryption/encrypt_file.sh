#!/bin/bash

if [ $# != "2" ]; then
  echo "Usage $0 mydata.txt mydata.enc"
  exit 1
fi

openssl enc -aes-256-cbc -salt -in $1 -out $2

if [ $? != 0 ]; then
  echo "Error"
else
  echo "Done"
fi


