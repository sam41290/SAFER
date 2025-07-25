#!/bin/bash

TOOL_PATH="/huge/soumyakant/BinaryAnalysis/bin_analysis_tools/safer"

if [ $# -lt 1 ]
then
    echo "Please specify program name as command line argument"
    exit 1
fi

exe_path=$1

args=""
argstogrep=""

if [ $# -eq 2 ]
then
    args=$2
    argstogrep=${2}
elif [ $# -eq 3 ]
then
    args=$2' '$3
    argstogrep=${2}"\n"${3}
elif [ $# -eq 4 ]
then
    args=$2' '$3' '$4;
    argstogrep=${2}"\n"${3}"\n"${4}
elif [ $# -eq 5 ]
then
	args=$2' '$3' '$4' '$5;
    argstogrep=${2}"\n"${3}"\n"${4}"\n"${5}
elif [ $# -eq 6 ]
then
    args=$2' '$3' '$4' '$5' '$6;
    argstogrep=${2}"\n"${3}"\n"${4}"\n"${5}"\n"${6}
elif [ $# -eq 7 ]
then
    args=$2' '$3' '$4' '$5' '$6' '$7;
    argstogrep=${2}"\n"${3}"\n"${4}"\n"${5}"\n"${6}"\n"${7}
fi

echo "instrument args"
echo "$args"

rand_mode=`echo $argstogrep | grep "rand_mode" | cut -d"=" -f2`

echo "rand_mode: ${rand_mode}"
#echo "$rand_mode"

len=`echo -n $rand_mode | wc -m`

if [ $len -le 0 ]
then
    rand_mode="NoRand"
fi

export LD_LIBRARY_PATH=/usr/lib/ocaml

REGEN_DIR="${HOME}/instrumented_libs"

linkdir=`dirname ${exe_path}`
linkdir=`readlink -f ${linkdir}`
#link=`find ${dir} -lname ${exe_path}`
filepath=`readlink -f ${exe_path}` 
echo "exe_path: ${exe_path} filepath: ${filepath}"
file=`basename ${filepath}`
link=($(find ${linkdir} -lname ${file}))
echo "${filepath}->${link}"
#len=`echo ${#link}`

if [ ${#link[@]} -eq 0 ]
then
  link=($(find ${linkdir} -lname ${filepath}))
  len=`echo ${#link}`
  echo "re-checked: ${filepath}->${link}"
fi

readelf -d ${filepath}
if [ $? -eq 0 ]
then
    pattern=`echo $file | sed 's/\./\\\./g'`
    mode=`cat ${TOOL_PATH}/scripts/randomized.dat | grep "^${pattern}:" | cut -d":" -f2`
    if [ "${mode}" = "${rand_mode}" ]
    then
        if [ ${#link[@]} -eq 0 ]
        then
          cp ${REGEN_DIR}/${file}_2 ${REGEN_DIR}/${file}
        else
          for l in "${link[@]}"
          do
            linkname=`basename ${l}`
            echo "linking $linkname -> ${file}_2"
            ln -sf ${REGEN_DIR}/${file}_2 ${REGEN_DIR}/${linkname}
          done
        fi
    else
        echo "processing ${filepath}"
        rm ${REGEN_DIR}/${file}_2
        cp ${filepath} ${REGEN_DIR}/
        ${TOOL_PATH}/scripts/instrument_binary.sh ${REGEN_DIR}/${file} ${args}
        mode_len=`echo ${#mode}`

        if [ ${mode_len} -eq 0 ]
        then
            echo "${file}:${rand_mode}" >> ${TOOL_PATH}/scripts/randomized.dat
        else
            sed -i "s/${pattern}:${mode}/${file}:${rand_mode}/g" \
            ${TOOL_PATH}/scripts/randomized.dat
        fi

        if [ ${#link[@]} -eq 0 ]
        then
            cp ${REGEN_DIR}/${file}_2 ${REGEN_DIR}/${file}
        else
            for l in "${link[@]}"
            do
                linkname=`basename ${l}`
                echo "linking $linkname -> ${file}_2"
                ln -sf ${REGEN_DIR}/${file}_2 ${REGEN_DIR}/${linkname}
            done
        fi
    fi
fi	

