#!/bin/sh

if [ $# -lt 1 ]
then
  echo "Inadequate commad line arguments. Usage: \
    \n arg 1: directory containing suite binaries\
    \n arg 2: randomization mode (rand_mode=BBR/ZJR/FR/PHR/FR/LLRK/PHRLLRK) [Optional]"
  exit
fi

#COREUTILS_SRC_DIR=${HOME}/coreutils-8.30/src

#COREUTILS_INSTALL=${HOME}/coreutils-install/bin

TOOL_PATH=${HOME}/SBI

suite_path=$1

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
INST_DIR="${suite_path}/inst_bins"
rm -rf ${INST_DIR}
cp ${suite_path}/jtable/*.jtable ${REGEN_DIR}/
cp ${suite_path}/jtable/*.sjtable ${REGEN_DIR}/
  
ls -1 ${suite_path}/* | grep -v "jtable" | grep -v "_orig" | grep -v "\.intercepted" | \
grep -v "_2" > all_bins.dat
#mkdir ${TOOL_PATH}/testsuite/data/coreutils_data_${i}
echo -n "" > ${TOOL_PATH}/testsuite/deps/suite_file_list.dat
while read line
do
  exe=`basename ${line}`
  ${TOOL_PATH}/testsuite/find_libs.sh ${line}
  cat ${TOOL_PATH}/testsuite/deps/${exe}_file_list.dat \
    >> ${TOOL_PATH}/testsuite/deps/suite_file_list.dat
done < all_bins.dat

sort -u ${TOOL_PATH}/testsuite/deps/suite_file_list.dat \
> ${TOOL_PATH}/testsuite/deps/tmp_file_list.dat

mv ${TOOL_PATH}/testsuite/deps/tmp_file_list.dat ${TOOL_PATH}/testsuite/deps/suite_file_list.dat

${TOOL_PATH}/testsuite/randomize_prog.sh suite
mkdir ${INST_DIR}
while read line
do
  exepath=`readlink -f ${line}`
  exe=`basename ${exepath}`
  echo "Copying instrumented ${exe}"
  if [ -f ${REGEN_DIR}/${exe}_2 ]
  then
	  cp ${REGEN_DIR}/${exe}_2 ${INST_DIR}/${exe}
  else
    echo "Failure encountered for $exe"
  fi
done < ${TOOL_PATH}/testsuite/deps/suite_file_list.dat
