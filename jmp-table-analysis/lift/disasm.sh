#!/bin/bash

# FwdMap is a learning based system which automatically builds assembly to IR
# translators using code generators of modern compilers.
#
# Copyright (C) 2014 - 2015 by Niranjan Hasabnis and R.Sekar in Secure Systems
# Lab, Stony Brook University, Stony Brook, NY 11794.
#
# This program is free software; you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation; either version 2 of the License, or 
# (at your option) any later version. 
#
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# GNU General Public License for more details. 
#
# You should have received a copy of the GNU General Public License 
# along with this program; if not, write to the Free Software 
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.

# 
# Dump assembly of a binary in a friendly manner for our learning tool.
# -t option dumps only text section.
#
# Remove lines not containing '<' in objdump output
#
# Also fixes some of mnemonic mismatches between objdump and assembler.
#

if [ $# -ne 3 -a $# -ne 2 ]
then
	>&2 echo "Usage: $0 <binary> [-t] x64|arm|avr"
	exit 0
fi

onlytext=""
if [ "$2" = "-t" ] 
then
onlytext="-j.text"
arch=$3
else
arch=$2
fi

if [ "${arch}" = "x64" ]
then
#objdump -d "${onlytext}" --prefix-addresses -M suffix "${1}" \
#	| sed '/</!d' | cut -d '>' -f 2 | cut -d '<' -f 1 | cut -d ' ' -f 2- \
#	| sed 's/080[0-9]*[a-f]*/0x&/'
objdump -d ${onlytext} --prefix-addresses -M suffix "${1}" \
	| grep "^0" \
	| awk '{$2=""; print $0}' \
	| cut -d '<' -f 1  \
	| sed 's/0x080/080/g' \
	| sed -r 's/(0[0-9a-f]+)[ \t]+/.L0x\1 /g' \
	| sed -r 's/\(([^,]+),([^,]+),1\)/(\1,\2)/g' \
	| sed -r 's/shl/sal/g' \
	| sed -r 's/%eiz//g' \
	| sed -r 's/\bcallq\b/call/g' \
	| sed -r 's/\bjmpq\b/jmp/g' \
	| sed -r 's/\bretq\b/ret/g' \
	| sed -r 's/\brepz ret\b/rep ret/g' \
	| sed -r 's/\b(cmov[a-z]+)l\b/\1/g' \
	| sed -r 's/\b(j[a-z]+)l\b/\1/g' \
	| sed -r 's/\bfildll\b/fildl/g' \
	| sed -r 's/(rep[a-z]*) ([^ ]+) (.*)/\1 \2/g' \
	| sed -r 's/(movsb) (.*)/\1/g' \
	| sed -e '/p2align/{N;d;}' \
		-e 's/st(0)/st0/g' \
		-e 's/st0(0)/st0/g' \
		-e 's/st(1)/st1/g' \
		-e 's/st1(1)/st1/g' \
		-e 's/st(2)/st2/g' \
		-e 's/st2(2)/st2/g' \
		-e 's/st(3)/st3/g' \
		-e 's/st3(3)/st3/g' \
		-e 's/st(4)/st4/g' \
		-e 's/st4(4)/st4/g' \
		-e 's/st(5)/st5/g' \
		-e 's/st5(5)/st5/g' \
		-e 's/st(6)/st6/g' \
		-e 's/st6(6)/st6/g' \
		-e 's/st(7)/st7/g' \
		-e 's/st7(7)/st7/g' \
		-e 's/st(8)/st8/g' \
		-e 's/st8(8)/st8/g' \
	| sed -r '/call\s+.*(eax|edx|ebx|ecx| \
						edx|ebp|esp|esi|edi).*/!{s/call\s+(\S*)/call \1/}' \
	| sed 's/\bleavel\b/leave/g' \
	| sed 's/\bfistpll\b/fistpl/g' \
	| sed -r 's/fnstsw %ax/fnstsw/g' \
	| sed 's/#.*//' \
	| awk '{print $0";";}' 
	#| grep "^.L0x"
elif [ "${arch}" = "arm" ]
then
arm-linux-gnueabi-objdump -d --prefix-addresses "${1}"  \
	| awk '{$2=""; print $0}' | cut -d '<' -f 1 \
	| sed 's/000[0-9]*[a-f]*/.L0x&/g' \
	| grep "^.L0x" \
	| cut -d ';' -f 1 \
	| awk '{print $0";"}'
elif [ "${arch}" = "avr" ]
then
avr-objdump -d --prefix-addresses "${1}" \
	| awk '{$2=""; print $0}' | cut -d ';' -f 1 \
	| sed 's/000[0-9]*[a-f]*/.L0x&/g' \
	| grep "^.L0x" \
	| sed -e 's/X/r26/g' \
	      -e 's/Y/r28/g' \
	      -e 's/Z/r30/g' \
	| awk '{print $0}'
else
	>&2 echo "Unknown architecture: ${arch}"
fi
