#!/bin/sh

TOOL_PATH=${HOME}/SBI

if [ $# -lt 1 ]
then
    echo "Please specify program name as command line argument"
    exit 1
fi

prog=$1

REGEN_DIR="${HOME}/randomized_libs"

echo -n "" > ${TOOL_PATH}/testsuite/${prog}_restore.sh 
echo -n "" > ${TOOL_PATH}/testsuite/${prog}_replace.sh

while read line
do
	linkdir=`dirname ${line}`
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
	
	if [ ${len} -eq 0 ]
    then
		echo "sudo cp ${filepath} ${filepath}_orig" >> ${TOOL_PATH}/testsuite/${prog}_replace.sh
        echo "sudo cp ${REGEN_DIR}/${file}.intercepted ${filepath}" >> ${TOOL_PATH}/testsuite/${prog}_replace.sh
		echo "sudo cp ${filepath}_orig ${filepath}" >> ${TOOL_PATH}/testsuite/${prog}_restore.sh
    else
		echo "sudo cp ${REGEN_DIR}/${file}.intercepted ${filepath}.intercepted" >> ${TOOL_PATH}/testsuite/${prog}_replace.sh
        echo "sudo ln -sf ${filepath}.intercepted ${line}" >> ${TOOL_PATH}/testsuite/${prog}_replace.sh
		echo "sudo ln -sf ${filepath} ${line}" >> ${TOOL_PATH}/testsuite/${prog}_restore.sh
    fi

done < ${TOOL_PATH}/testsuite/deps/${prog}_file_list.dat

ln -sf ${TOOL_PATH}/testsuite/${prog}_restore.sh ${HOME}/${prog}_restore.sh
ln -sf ${TOOL_PATH}/testsuite/${prog}_replace.sh ${HOME}/${prog}_replace.sh
