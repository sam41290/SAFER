#!/bin/bash
dlist=$1
thread=$2

ev=~/test/eval
sba=~/SBI/src/sbi/jtable/test_type

tmp=/tmp/sbr2
dir=$tmp/$thread
mkdir -p $dir
rm -rf $dir/*
awk -v var=$thread 'FNR%10==var' $dlist > $dir/dlist
g++ -g -std=c++2a $ev.cpp -o $dir/eval;

hex2dec() {
   {
      echo 'ibase=16';
      sed -e 'y/xabcdef/XABCDEF/' -e 's/^0X//';
   } | bc
}

while read -r dpath <&3
do
   rm -rf $dir/lift/* $dir/obj.func $dir/obj.type $dir/sba.type
   cp $dpath/* $dir

   # test ! -f "$dir/obj.func" && timeout 600s $dir/eval $dir dec type_input

   if [ -s $dir/obj.func ]; then
      # cp $dir/obj.func $dpath
      # cp $dir/obj.type $dpath
      objdump --prefix-addresses -d $dir/ori | grep '^0' | cut -d' ' -f1 | sed 's/^0*//' | hex2dec > $dir/obj.offset
      readelf -r $dir/ori | grep -E 'R_X86_64_IRELATIV|R_X86_64_RELATIVE' | awk '{print $4}' | hex2dec > $dir/obj.relocs
      $sba $tmp $thread >/dev/null 2>&1
exit
      sort -u $dir/obj.type -o $dir/obj.type
      sort -u $dir/sba.type -o $dir/sba.type
      $dir/eval $dir dec type
   fi

   # objdump --prefix-addresses -d $dir/ori | grep '^0' > $dir/obj.s
   # cut -d' ' -f2- $dir/obj.s > $dir/temp
   # cut -d' ' -f3- $dir/obj.s > $dir/temp2
   # cut -d' ' -f1 $dir/obj.s > $dir/obj.hex
   # cut -d' ' -f1 $dir/obj.s | sed 's/^0*//' | hex2dec > $dir/obj.dec
   # paste -d"\t" $dir/obj.dec $dir/obj.hex $dir/temp > $dir/obj.s
   # paste -d"\t" $dir/obj.dec $dir/obj.hex $dir/temp2 > $dir/obj2.s
done 3<$dir/dlist

