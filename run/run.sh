#!/bin/sh

cfgdir=$2
disasm=$3

#make

rm -rf jmp_table log tmp *.o *.s text

mkdir jmp_table
mkdir log
mkdir tmp
mkdir tmp/cfg

file=`basename $1`

if [ "${disasm}" = "symtabledisasm" ]; then
  objdump -W ${1} | grep "advance Address by" \
      | gawk --non-decimal-data '{printf("%d\n",$10)}' \
      > tmp/${file}.ptrlst
#  readelf --debug-dump=decodedline ${1} | grep -v "name\|section\|CU:" \
 #   | gawk --non-decimal-data '{if (NF >= 3) printf("%d\n",$3)}' | sort -u >> tmp/${file}.ptrlst
fi

if [ -d "${cfgdir}" ]
then
  cp -r ${cfgdir} tmp/
  echo "cfg present" > tmp/cfg.present
fi

exe=`basename $1`

cp $1 ./tmp/${exe}

export LD_LIBRARY_PATH=/usr/lib/ocaml:${HOME}/SBI/src/rtl-analysis

if [ "${disasm}" = "symtabledisasm" ]; then
  ./demo $1
else
  strip ./tmp/${exe}
  ./demo ./tmp/${exe}
fi
if [ -f "./tmp/${exe}_2" ]
then
  cp ./tmp/${exe}_2 ${1}_2
fi
