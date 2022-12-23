#!/bin/sh

#if [ $# -lt 2 ]
#then
#  echo "Inadequate commad line arguments. Usage: \
#    \n arg 2: randomization mode (rand_mode=BBR/ZJR/FR/PHR/FR/LLRK/PHRLLRK) [Optional]\
#    \n arg 3: eh optimization (eh_opt=yes/no) [Optional]"
#  exit
#fi

COREUTILS_SRC_DIR=${HOME}/coreutils-8.30/src

COREUTILS_INSTALL=${HOME}/coreutils-install/bin
COREUTILS_LIB=${HOME}/coreutils-install/libexec/coreutils

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

REGEN_DIR="${HOME}/randomized_libs"

#while [ $i -lt $seeds ]
#do
  #rm ${COREUTILS_INSTALL}/*_2
  #rm ${COREUTILS_INSTALL}/*.log
  
  ls -1 ${COREUTILS_INSTALL}/* | grep -v "_orig" | grep -v "\.intercepted" | \
  grep -v "_2" | grep -v "\.o\|\.c\|\.h" > all_bins.dat
  ls -1 ${COREUTILS_LIB}/* | grep -v "_orig" | grep -v "\.intercepted" | \
  grep -v "_2" | grep -v "\.o\|\.c\|\.h" >> all_bins.dat
  #mkdir ${TOOL_PATH}/testsuite/data/coreutils_data_${i}
  echo -n "" > ${TOOL_PATH}/testsuite/deps/coreutils_file_list.dat
  while read line
  do
    exe=`basename ${line}`
    ${TOOL_PATH}/testsuite/find_libs.sh ${line}
    cat ${TOOL_PATH}/testsuite/deps/${exe}_file_list.dat >> ${TOOL_PATH}/testsuite/deps/coreutils_file_list.dat
  done < all_bins.dat

  sort -u ${TOOL_PATH}/testsuite/deps/coreutils_file_list.dat \
  > ${TOOL_PATH}/testsuite/deps/tmp_file_list.dat

  mv ${TOOL_PATH}/testsuite/deps/tmp_file_list.dat ${TOOL_PATH}/testsuite/deps/coreutils_file_list.dat

  ${TOOL_PATH}/testsuite/randomize_prog.sh coreutils
  ${tool_path}/testsuite/randomize_prog.sh libnss_files.so.2
  ${tool_path}/testsuite/randomize_prog.sh libnss_systemd.so.2
  while read line
  do
    exe=`basename ${line}`
    if [ -f ${REGEN_DIR}/${exe}_2 ]
    then
      chmod 777 ${REGEN_DIR}/${exe}_2
  	  cp ${REGEN_DIR}/${exe}_2 ${COREUTILS_SRC_DIR}/${exe}
    else
      echo "Failure encountered for $exe"
      exit
    fi
  done < all_bins.dat

  #while read line
  #do
  #	echo "---------------------------------"
  #	echo "randomizing $line"
  #	echo "---------------------------------"
  #
  #  exename=`basename $line`
  #
  #	${TOOL_PATH}/randomize.sh ${line} ${args}
  #  cp ${line}.log ${TOOL_PATH}/testsuite/data/coreutils_data_${i}/
  #  cp ${TOOL_PATH}/run/${exename}_new.s ${TOOL_PATH}/testsuite/data/coreutils_data_${i}/
  #  if [ -f ${line}_2 ]
  #  then
  #	  cp ${line}_2 ${COREUTILS_SRC_DIR}/${exename}
  #  else
  #    echo "Failure encountered for $exename"
  #    exit
  #  fi
  #
  #done < all_bins.dat

  #cd ${COREUTILS_SRC_DIR}/..
  #export INST_LIBS=${REGEN_DIR}
  #time make check RUN_EXPENSIVE_TESTS=yes RUN_VERY_EXPENSIVE_TESTS=yes #> test.log
  #cp test.log ${thisdir}/data/coreutils_data_${i}/
  #cd ${thisdir}

  #i=`expr $i + 1`
#done
