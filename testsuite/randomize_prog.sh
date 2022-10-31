#!/bin/bash

date

TOOL_PATH=${HOME}/SBI

if [ $# -lt 1 ]
then
	echo "Please specify program name as command line argument"
	exit 1
fi

prog=$1

args=""

if [ $# -eq 2 ]
then
    args=$2
elif [ $# -eq 3 ]
then
    args=$2'\n'$3
elif [ $# -eq 4 ]
then
    args=$2'\n'$3'\n'$4;
fi

rand_mode=`echo $args | grep "rand_mode" | cut -d"=" -f2`

len=`echo -n $rand_mode | wc -m`

if [ $len -le 0 ]
then
    rand_mode="NoRand"
fi

export LD_LIBRARY_PATH=/usr/lib/ocaml


REGEN_DIR="${HOME}/randomized_libs"

while read line
do
	linkdir=`dirname ${line}`
	#link=`find ${dir} -lname ${line}`
	filepath=`readlink -f ${line}` 
	echo "line: ${line} filepath: ${filepath}"
	file=`basename ${filepath}`
	link=`find ${linkdir} -lname ${file}`
	len=`echo ${#link}`

	if [ ${len} -eq 0 ]
	then
	  link=`find ${linkdir} -lname ${filepath}`
      len=`echo ${#link}`
	fi

	readelf -d ${filepath}
	if [ $? -eq 0 ]
	then
		pattern=`echo $file | sed 's/\./\\\./g'`
		mode=`cat ${TOOL_PATH}/testsuite/randomized.dat | grep "^${pattern}" | cut -d":" -f2`
		if [ "${mode}" = "${rand_mode}" ]
		then
			if [ ${len} -eq 0 ]
        	then
        	    cp ${REGEN_DIR}/${file}_2 ${REGEN_DIR}/${file}
        	else
        	    linkname=`basename ${link}`
        	    ln -sf ${REGEN_DIR}/${file}_2 ${REGEN_DIR}/${linkname}
        	fi

			continue
		fi


		echo "processing ${filepath}"
        rm ${REGEN_DIR}/${file}_2
		cp ${filepath} ${REGEN_DIR}/
    	${TOOL_PATH}/randomize.sh ${REGEN_DIR}/${file} ${args}
		
		mode_len=`echo ${#mode}`

		if [ ${mode_len} -eq 0 ]
		then
			echo "${file}:${rand_mode}" >> ${TOOL_PATH}/testsuite/randomized.dat
		else
			sed -i "s/${pattern}:${mode}/${file}:${rand_mode}/g" \
            ${TOOL_PATH}/testsuite/randomized.dat
		fi

    	if [ ${len} -eq 0 ]
    	then
    	    cp ${REGEN_DIR}/${file}_2 ${REGEN_DIR}/${file}
    	else
			linkname=`basename ${link}`
    	    ln -sf ${REGEN_DIR}/${file}_2 ${REGEN_DIR}/${linkname}
    	fi

	fi	

done < ${TOOL_PATH}/testsuite/deps/${prog}_file_list.dat 

date
