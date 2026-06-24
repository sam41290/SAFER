#!/bin/bash
TOOL_PATH=/huge/soumyakant/BinaryAnalysis/bin_analysis_tools/safer

disasm_only=$2
dumpcfg=$3

#make


file=`basename $1`
file_dir=`dirname $1`
jtable=${file_dir}/${file}.jtable
sjtable=${file_dir}/${file}.sjtable

if [ -f "${jtable}" ]
then
  cp -r ${jtable} jmp_table/result.jtable
else
  export LD_LIBRARY_PATH=/usr/lib/ocaml:${TOOL_PATH}/jtable_cache
  ${TOOL_PATH}/jtable_cache/test_jtable $1 jmp_table/result.jtable ${TOOL_PATH}/auto/output.auto  
fi
if [ -f "${sjtable}" ]
then
  cp -r ${sjtable} jmp_table/result.sjtable
fi



exe=`basename $1`

wd=`pwd`

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"

cd ${SCRIPT_DIR}

rm -rf jmp_table log tmp *.o *.s text

mkdir jmp_table
mkdir log
mkdir tmp
mkdir tmp/cfg

cp $1 ${SCRIPT_DIR}/tmp/${exe}

export LD_LIBRARY_PATH=/usr/lib/ocaml:${TOOL_PATH}/src/SBD/analysis
./app ./tmp/${exe} ${disasm_only} ${dumpcfg}

if [ -f "${SCRIPT_DIR}/tmp/${exe}_2" ]
then
  cp ${SCRIPT_DIR}/tmp/${exe}_2 ${1}_2
  chmod 777 ${SCRIPT_DIR}/tmp/${exe}_2 ${1}_2
fi

cd $wd
