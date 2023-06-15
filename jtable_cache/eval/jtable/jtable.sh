#!/bin/bash
dlist=$1
thread=$2

ev=~/test/eval
sba=~/SBI/src/SBA/test_jtable
#sba=~/SBI/src/SBA/test_func
angr=~/x86-sok/disassemblers/angr/angrBlocks.py
ddisasm_edge=~/test/ddisasm_edge.py

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
   find $dir -type f -not \( -name "dlist" -o -name "bounds" -o -name "time" -o -name "stat.*" -o -name "eval" \) -delete
   cp $dpath/* $dir
   
   # results from previous run
   # tar -C $dir -xf $dir/log_sba.tar.xz
   tar -C $dir -xf $dir/log_gt.tar.xz
   tar -C $dir -xf $dir/log_angr.tar.xz
   tar -C $dir -xf $dir/log_dyninst.tar.xz
   tar -C $dir -xf $dir/log_ghidra.tar.xz
   tar -C $dir -xf $dir/log_ddisasm.tar.xz

   # function entries
   # grep "Get Function Addr" $dir/log.dyninst | cut -d' ' -f4 | cut -d'.' -f1 >> $dir/obj.func
   # cat $dir/functions >> $dir/obj.func
   # grep "Found function" $dir/log.gt | cut -d' ' -f3 > $dir/obj.func
   # nm -S $dir/ori | grep '^0' | grep -E ' T | t ' | sed 's/^0*//' | cut -d' ' -f1 | hex2dec >> $dir/obj.func
   # sort -u $dir/obj.func -o $dir/obj.func
   # objdump --prefix-addresses -d $dir/ori | grep '^0' | cut -d' ' -f1 | sed 's/^0*//' | hex2dec > $dir/obj.offset

   # sba
   /usr/bin/time -p -o $dir/runtime.sba $sba $tmp $thread >/dev/null 2>&1
   sort -u $dir/sba.jtable -o $dir/sba.jtable 
   tar -C $dir -cJf $dpath/log_sba.tar.xz log.sba sba.jtable sba.icf
   cp $dir/runtime.sba $dpath

   # angr
   # /usr/bin/time -p -o $dir/runtime.angr python3 $angr --binary $dir/obj --output $dir/temp > $dir/log.angr
   # tar -C $dir -cJf $dpath/log_angr.tar.xz log.angr
   # cp $dir/runtime.angr $dpath

   # ddisasm
   # /usr/bin/time -p -o $dir/runtime.ddisasm ddisasm $dir/obj --ir $dir/ddisasm.gtirb
   # python3 $ddisasm_edge $dir/ddisasm.gtirb > $dir/log.ddisasm
   # tar -C $dir -cJf $dpath/log_ddisasm.tar.xz log.ddisasm
   # cp $dir/runtime.ddisasm $dpath

   # eval
   objdump --prefix-addresses -d $dir/ori | grep '^0' > $dir/obj.s
   $dir/eval $dir dec
   cut -d' ' -f2- $dir/obj.s > $dir/temp
   cut -d' ' -f3- $dir/obj.s > $dir/temp2
   cut -d' ' -f1 $dir/obj.s > $dir/obj.hex
   cut -d' ' -f1 $dir/obj.s | sed 's/^0*//' | hex2dec > $dir/obj.dec
   paste -d"\t" $dir/obj.dec $dir/obj.hex $dir/temp > $dir/obj.s
   paste -d"\t" $dir/obj.dec $dir/obj.hex $dir/temp2 > $dir/obj2.s

   # bounds
   echo $dpath >> $dir/bounds
   grep "jtentry_gt:" $dir/eval.sba >> $dir/bounds
   grep "jtentry_correct_" $dir/eval.* | cut -d':' -f2- >> $dir/bounds
   grep "jtentry_over_" $dir/eval.* | cut -d':' -f2- >> $dir/bounds
   grep "jtentry_under_" $dir/eval.* | cut -d':' -f2- >> $dir/bounds

   # time
   size $dir/obj | tail -n 1 | awk '{print $1/1024}' > $dir/temp              #1:  code_size
   grep "\-\-> #analysed_insn" $dir/log.sba | awk '{print $4}' >> $dir/temp   #2:  analysed_insn
   grep "\-\-> lift:" $dir/log.sba | awk '{print -$3*20/20}' >> $dir/temp
   grep "real" $dir/runtime.sba | awk '{print $2}' >> $dir/temp
   tail -n 2 $dir/temp | awk '{s+=$1} END {print s}' >> $dir/temp             #3:  time_sba
   grep "real" $dir/runtime.angr | awk '{print $2}' >> $dir/temp              #4:  time_angr
   grep "real" $dir/runtime.dyninst | awk '{print $2}' >> $dir/temp           #5:  time_dyninst
   grep "real" $dir/runtime.ghidra | awk '{print $2}' >> $dir/temp            #6:  time_ghidra
   grep "real" $dir/runtime.ddisasm | awk '{print $2}' >> $dir/temp           #7:  time_ddisasm
   grep "\-\-> analysis:" $dir/log.sba | awk '{print $3}' >> $dir/temp        #8:  time_sba_analysis
   grep "\-\-> cfg:" $dir/log.sba | awk '{print $3}' >> $dir/temp             #9:  time_sba_cfg
   grep "\-\-> parse:" $dir/log.sba | awk '{print $3}' >> $dir/temp           #10: time_sba_parse
   tail -n 12 $dir/temp | tr '\n' ' ' >> $dir/temp
   echo "---------------------------------------------------------------------" >> $dir/time
   echo $dpath >> $dir/time
   tail -n 1 $dir/temp | awk '{print "size: " $1 "\ninsn: " $2 "\nsba: " $5 "\nangr: " $6 "\ndyninst: " $7 "\nghidra: " $8 "\nddisasm: " $9 "\nsba_analysis: " $10 "\nsba_cfg: " $11 "\nsba_lift: " $12}' >> $dir/time
   tail -n 1 $dir/temp | awk '{print $1, $2, $5, $6, $7, $8, $9, $10, $11, $12}' >> $dir/stat.time
done 3<$dir/dlist
