#!/bin/bash

while true;
do
	echo "Starting service"
	/bin/nc.traditional -l -p 33333 -e ./ropasaurusrex
	
	# Put a sleep in here between runs to give you a chance to exit script
	sleep 2
done

