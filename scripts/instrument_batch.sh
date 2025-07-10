#!/bin/sh

TOOL_PATH="/huge/soumyakant/BinaryAnalysis/bin_analysis_tools/safer"

if [ $# -lt 1 ]
then
    echo "Please specify program name as command line argument"
    exit 1
fi

batch_file=$1

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

echo "instrument_batch args"
echo "$args"

rand_mode=`echo $args | grep "rand_mode" | cut -d"=" -f2`
echo "instrument_batch rand_mode ${rand_mode}"
#echo "$rand_mode"

len=`echo -n $rand_mode | wc -m`

if [ $len -le 0 ]
then
    rand_mode="NoRand"
fi

while read line
do
  ${TOOL_PATH}/script/instrument.sh ${line} ${args}
done < ${batch_file}
