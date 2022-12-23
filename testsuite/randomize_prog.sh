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

exe_cnt=`cat ${TOOL_PATH}/testsuite/deps/${prog}_file_list.dat | wc -l`
max_batch_cnt=`expr $exe_cnt / 7`
echo "batch count: ${max_batch_cnt}"

batch_cnt=0
batch_num=1
batch_file="/tmp/${prog}_batch_${batch_num}"
echo -n "" > ${batch_file}

while read line
do
  echo "${line}" >> ${batch_file}
  batch_cnt=`expr $batch_cnt + 1`
  if [ $batch_cnt -ge $max_batch_cnt ]
  then
    nohup ${TOOL_PATH}/testsuite/instrument_batch.sh ${batch_file} ${arg} &
    batch_cnt=0
    batch_num=`expr $batch_num + 1`
    batch_file="/tmp/${prog}_batch_${batch_num}"
    echo -n "" > ${batch_file}
  fi
  #${TOOL_PATH}/testsuite/instrument.sh ${REGEN_DIR}/${file} ${args}
done < ${TOOL_PATH}/testsuite/deps/${prog}_file_list.dat 
if [ $batch_cnt -lt $max_batch_cnt ]
then
  nohup ${TOOL_PATH}/testsuite/instrument_batch.sh ${batch_file} ${arg} &
fi

wait

date
