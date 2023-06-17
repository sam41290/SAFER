#!/bin/sh

TOOL_PATH=/${HOME}/SBI

if [ $# -lt 1 ]
then
  echo "Inadequate commad line arguments. Usage: \
    \n arg 1: Full path of executable to be randomized\
    \n arg 2: randomization mode (rand_mode=BBR/ZJR/FR/PHR/FR/LLRK/PHRLLRK) [Optional]\
    \n arg 3: eh optimization (eh_opt=yes/no) [Optional]"
  exit
fi


binpath=$1

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


echo "parameters:"
echo $args

rand_mode=`echo $args | grep "config" | cut -d"=" -f2`

len=`echo -n $rand_mode | wc -m`

if [ $len -le 0 ]
then
	rand_mode="default"
fi

ehopt=`echo $args | grep "eh_opt" | cut -d"=" -f2`

len=`echo -n $ehip | wc -m`

if [ $len -le 0 ]
then
    eh_opt=0
fi

if [ "$ehopt" = "no" ]; then
  eh_opt=0
fi


export LD_LIBRARY_PATH=/usr/lib/ocaml

bin=`basename $binpath`
mkdir ${TOOL_PATH}/${bin}_run
cp -r ${TOOL_PATH}/run/* ${TOOL_PATH}/${bin}_run/
wd=`pwd`
cd ${TOOL_PATH}/${bin}_run

change_config=`diff config.h randmodes/${rand_mode}.h | wc -w`

if [ $change_config -gt 0 ]
then
  cp randmodes/${rand_mode}.h config.h
  make clean
fi

#make clean
make
./run.sh $binpath > ${binpath}.log
cd ${wd}
rm -rf ${TOOL_PATH}/${bin}_run

