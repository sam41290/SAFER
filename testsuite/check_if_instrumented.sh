#!/bin/sh


while read line
do
	lib=`echo $line | cut -d":" -f1`
	file=/home/soumyakant/table-1-progs/${lib}.intercepted
	if [ -f "${file}" ]
	then
		echo -n ""
	else
		echo "$lib"
	fi
done < randomized.dat
