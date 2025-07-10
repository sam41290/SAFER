#!/bin/sh

TOOL_PATH=/${HOME}/SBI

if [ $# -lt 1 ]
then
  echo "Inadequate commad line arguments. Usage: \
    \n arg 1: Full path of executable to be randomized\
    \n arg 2: Disasm mode (disasm=EH_disasm/ABI/FN_PRLG/valid_ins) [Optional]\
    \n arg 3: Pointer translation mode
      (ptr_trans=static/FULL_AT/FULL_enc/RA_Opt/Safe_jtable/default) [Optional]\
    \n arg 4: randomization mode (rand_mode=BBR/ZJR/FR/PHR/FR/LLRK/PHRLLRK) [Optional]\
    \n arg 5: eh optimization (eh_opt=yes/no) [Optional]"
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
elif [ $# -eq 5 ]
then
	args=$2'\n'$3'\n'$4'\n'$5;
elif [ $# -eq 6 ]
then
	args=$2'\n'$3'\n'$4'\n'$5'\n'$6;
elif [ $# -eq 7 ]
then
	args=$2'\n'$3'\n'$4'\n'$5'\n'$6'\n'$7;
fi


echo "parameters:"
echo $args

rand_mode=`echo $args | grep "rand_mode" | cut -d"=" -f2`
echo "rand_mode:"
echo "$rand_mode"

len=`echo -n $rand_mode | wc -m`

if [ $len -le 0 ]
then
	rand_mode="NoRand"
fi

disasm=`echo $args | grep "disasm" | cut -d"=" -f2`
echo "disasm:"
echo "$disasm"

len=`echo -n $disasm | wc -m`

if [ $len -le 0 ]
then
	disasm="ABI"
fi

ptr_trans=`echo $args | grep "ptr_trans" | cut -d"=" -f2`
echo "ptr_trans:"
echo "$ptr_trans"

len=`echo -n $ptr_trans | wc -m`

if [ $len -le 0 ]
then
	ptr_trans="default"
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


app=`echo $args | grep "app" | cut -d"=" -f2`
echo "Application:"
echo "$app"

len=`echo -n $app | wc -m`

if [ $len -le 0 ]
then
    app="default_instrument"
fi

export LD_LIBRARY_PATH=/usr/lib/ocaml

bin=`basename $binpath`
mkdir ${TOOL_PATH}/apps/${bin}_run
cp -r ${TOOL_PATH}/apps/${app}/* ${TOOL_PATH}/${bin}_run/
wd=`pwd`

#if [ $change_config -gt 0 ]
#then
  cd ${TOOL_PATH}/configs
  cp randmodes/${rand_mode}.h rand_config.h
  cp disasmConfig/${disasm}.h disasm_config.h
  cp ptrTransConfig/${ptr_trans}.h ptr_trans_config.h
  #make clean
#fi

cd ${TOOL_PATH}/apps/${bin}_run
#make clean
make
./run $binpath > ${binpath}.log
cd ${wd}
rm -rf ${TOOL_PATH}/${bin}_run

