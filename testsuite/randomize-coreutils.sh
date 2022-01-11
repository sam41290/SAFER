#!/bin/sh

if [ $# -lt 1 ]
then
  echo "Inadequate commad line arguments. Usage: \
    \n arg 1: randomization seeds\
    \n arg 2: randomization mode (rand_mode=BBR/ZJR/FR/PHR/FR/LLRK/PHRLLRK) [Optional]\
    \n arg 3: eh optimization (eh_opt=yes/no) [Optional]"
  exit
fi

COREUTILS_SRC_DIR=${HOME}/coreutils-8.32/src

COREUTILS_INSTALL=${HOME}/coreutils-nopie/bin

TOOL_PATH=${HOME}/SBI

seeds=$1

args=""

if [ $# -eq 2 ]
then
	args=$2
elif [ $# -eq 3 ]
then
    args=$2' '$3
elif [ $# -eq 4 ]
then
    args=$2' '$3' '$4
elif [ $# -eq 5 ]
then
    args=$2' '$3' '$4' '$5;
fi

i=0

thisdir=`pwd`

while [ $i -lt $seeds ]
do
  rm ${COREUTILS_INSTALL}/*_2
  rm ${COREUTILS_INSTALL}/*.log
  
  ls -1 ${COREUTILS_INSTALL}/* | grep -v "_orig" | grep -v "\.intercepted" | \
  grep -v "_2" > all_bins.dat
  mkdir ${TOOL_PATH}/testsuite/data/coreutils_data_${i}
  while read line
  do
  	echo "---------------------------------"
  	echo "randomizing $line"
  	echo "---------------------------------"
  
    exename=`basename $line`
  
  	${TOOL_PATH}/randomize.sh ${line} ${args}
    cp ${line}.log ${TOOL_PATH}/testsuite/data/coreutils_data_${i}/
    cp ${TOOL_PATH}/run/${exename}_new.s ${TOOL_PATH}/testsuite/data/coreutils_data_${i}/
    if [ -f ${line}_2 ]
    then
  	  cp ${line}_2 ${COREUTILS_SRC_DIR}/${exename}
    else
      echo "Failure encountered for $exename"
      exit
    fi
  
  done < all_bins.dat

  cd ${COREUTILS_SRC_DIR}/..
  make check RUN_EXPENSIVE_TESTS=yes RUN_VERY_EXPENSIVE_TESTS=yes #> test.log
  #cp test.log ${thisdir}/data/coreutils_data_${i}/
  cd ${thisdir}

  i=`expr $i + 1`
done
