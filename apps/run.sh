#!/bin/sh
TOOL_PATH=/huge/soumyakant/BinaryAnalysis/bin_analysis_tools/safer

disasm_only=$2
dumpcfg=$3

#make

rm -rf jmp_table log tmp *.o *.s text

mkdir jmp_table
mkdir log
mkdir tmp
mkdir tmp/cfg

file=`basename $1`
file_dir=`dirname $1`
jtable=${file_dir}/${file}.jtable
sjtable=${file_dir}/${file}.sjtable


export LD_LIBRARY_PATH=/usr/lib/ocaml:${TOOL_PATH}/jtable_cache
${TOOL_PATH}/jtable_cache/test_jtable $1 jmp_table/result.jtable ${TOOL_PATH}/auto/output.auto  

exe=`basename $1`

cp $1 ./tmp/${exe}

export LD_LIBRARY_PATH=/usr/lib/ocaml:${TOOL_PATH}/src/SBD/analysis

./app ./tmp/${exe} ${disasm_only} ${dumpcfg}

if [ -f "./tmp/${exe}_2" ]
then
  cp ./tmp/${exe}_2 ${1}_2
fi
