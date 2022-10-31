#!/bin/bash

# wget https://icanhazdadjoke.com/search?term=&page=2

#curl https://icanhazdadjoke.com/search?term=&page=2 > page2.txt



for i in {1..33}
do
	echo "Sleepng before download page $i"
	sleep 5

	curl "https://icanhazdadjoke.com/search?term=&page=$i" -o page$i.txt
done

