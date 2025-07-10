#!/bin/bash

date

TOOL_PATH="/huge/soumyakant/BinaryAnalysis/bin_analysis_tools/safer"

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
	args=$2' '$3
elif [ $# -eq 4 ]
then
	args=$2' '$3' '$4;
elif [ $# -eq 5 ]
then
	args=$2' '$3' '$4' '$5;
elif [ $# -eq 6 ]
then
	args=$2' '$3' '$4' '$5' '$6;
elif [ $# -eq 7 ]
then
	args=$2' '$3' '$4' '$5' '$6' '$7;
fi

#rand_mode=`echo $args | grep "config" | cut -d"=" -f2`
#
#len=`echo -n $rand_mode | wc -m`
#
#if [ $len -le 0 ]
#then
#    rand_mode="default"
#fi

export LD_LIBRARY_PATH=/usr/lib/ocaml


REGEN_DIR="${HOME}/instrumented_libs"

export LD_LIBRARY_PATH=/usr/lib/ocaml:${TOOL_PATH}/jtable_cache

while read line
do
  file=`readlink -f ${line}`
  exe=`basename $file`
  echo "Creating jump table cache: ${exe}"
  if [ -f "${REGEN_DIR}/${exe}.jtable" ]
  then
    echo "Jump table cache exists!!"
  else
    ${TOOL_PATH}/test_jtable ${file} ${REGEN_DIR}/${exe}.jtable ${TOOL_PATH}/auto/output.auto
  fi
done < ${TOOL_PATH}/scripts/deps/${prog}_file_list.dat

exe_cnt=`cat ${TOOL_PATH}/scripts/deps/${prog}_file_list.dat | wc -l`
max_batch_cnt=`expr $exe_cnt / 7`
echo "batch count: ${max_batch_cnt}"

batch_cnt=0
batch_num=1
batch_file="/tmp/${prog}_batch_${batch_num}"
echo -n "" > ${batch_file}
echo "instrument_prog args:"
echo "$args"
while read line
do
  echo "${line}" >> ${batch_file}
  batch_cnt=`expr $batch_cnt + 1`
  if [ $batch_cnt -ge $max_batch_cnt ]
  then
    nohup ${TOOL_PATH}/scripts/instrument_batch.sh ${batch_file} ${args} &
    batch_cnt=0
    batch_num=`expr $batch_num + 1`
    batch_file="/tmp/${prog}_batch_${batch_num}"
    echo -n "" > ${batch_file}
  fi
done < ${TOOL_PATH}/scripts/deps/${prog}_file_list.dat 
if [ $batch_cnt -lt $max_batch_cnt ]
then
  nohup ${TOOL_PATH}/scripts/instrument_batch.sh ${batch_file} ${args} &
fi

wait

date
