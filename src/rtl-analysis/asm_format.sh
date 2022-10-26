#!/bin/bash

cat "${1}" \
	| sed 's/0x080/080/g' \
	| sed -r 's/\.([0-9]+)+/.L\1/g' \
	| sed -r 's/\.L([0-9]+)+\:/.L\1/g' \
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
	| sed 's/[[:blank:]]*$//' \
	| awk '{print $0";";}' &> "${2}"