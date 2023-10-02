#!/bin/bash
dlist=$1
thread=$2

sba=./test_jtable
tmp=/tmp/sbr2
dir=$tmp/$thread
mkdir -p $dir
rm -rf $dir/*
awk -v var=$thread 'FNR%10==var' $dlist > $dir/dlist

hex2dec() {
   {
      echo 'ibase=16';
      sed -e 'y/xabcdef/XABCDEF/' -e 's/^0X//';
   } | bc
}

while read -r dpath <&3
do
   echo $dpath
   find $dir -type f -not \( -name "dlist" -o -name "cnt.total" -o -name "cnt.static" -o -name "cnt.dynamic" -o -name "result" \) -delete
   cp $dpath/* $dir
   $sba $tmp $thread $dpath >/dev/null 2>&1
   objdump --prefix-addresses -d $dir/ori > $dir/obj.s
   grep "sbi:" $dir/log.sba | sort -u | cut -c 6- > $dir/temp

   grep 'jmpq *\*' $dir/obj.s | grep -v '%rip' | grep '^0' | awk '{print $1}' | hex2dec > $dir/total
   grep -v "dynamic" $dir/temp | awk '{print $2}' > $dir/static
   grep "dynamic" $dir/temp | awk '{print $2}' > $dir/dynamic
   cat $dir/total | wc -l >> $dir/cnt.total
   comm -12 <(sort $dir/static) <(sort $dir/total) | wc -l >> $dir/cnt.static
   comm -12 <(sort $dir/dynamic) <(sort $dir/total) | wc -l >> $dir/cnt.dynamic
done 3<$dir/dlist

awk '{s+=$1} END {print s}' $dir/cnt.total > $dir/result
awk '{s+=$1} END {print s}' $dir/cnt.static >> $dir/result
awk '{s+=$1} END {print s}' $dir/cnt.dynamic >> $dir/result
tail -n 3 $dir/result | tr '\n' ' ' >> $dir/result
