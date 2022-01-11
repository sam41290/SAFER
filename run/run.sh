#!/bin/sh

cfgdir=$2
disasm=$3



make

rm -rf jmp_table log tmp/* *.o *.s text

mkdir jmp_table
mkdir log
#mkdir tmp
mkdir tmp/cfg

file=`basename $1`

if [ "${disasm}" = "symtabledisasm" ]; then
  objdump -W ${1} | grep "advance Address by" \
      | gawk --non-decimal-data '{printf("%d\n",$10)}' \
      > tmp/${file}.ptrlst
fi


if [ -d "${cfgdir}" ]
then
  cp -r ${cfgdir} tmp/
  echo "cfg present" > tmp/cfg.present
fi

exe=`basename $1`

export LD_LIBRARY_PATH=/usr/lib/ocaml:${HOME}/SBI/src/rtl-analysis

./demo $1
