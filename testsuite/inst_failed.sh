#!/bin/bash

date

TOOL_PATH=${HOME}/SBI

if [ $# -lt 1 ]
then
	echo "Please specify program name as command line argument"
	exit 1
fi

prog=$1



REGEN_DIR="${HOME}/instrumented_libs"


while read line
do
  file=`readlink -f ${line}`
  exe=`basename $file`
  if [ -f "${REGEN_DIR}/${exe}_2" ]
  then
    echo -n ""
  else
    echo "${exe}: FAIL"
    #${HOME}/SBI/jtable_cache/test_jtable ${file} ${REGEN_DIR}/${exe}.jtable ${HOME}/SBI/auto/output.auto
  fi
done < ${TOOL_PATH}/testsuite/deps/${prog}_file_list.dat

