#!/bin/sh

while [ 1 == 1 ]; do 

	a=$(shuf -i 0-10000 -n 1) 
	b=$(shuf -i 0-10000 -n 1)
	echo $((a * b))  

done
