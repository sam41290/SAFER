.65241: nopl (%rax) 
.65248: flds .114572(%rip) 
.65254: fldt 8(%rsp) 
.65258: fcomi %st(1) 
.65260: jae .65376 
.65262: fstp %st(1) 
.65264: fnstcw -0xa(%rsp) 
.65268: movzwl -0xa(%rsp), %eax 
.65273: orb $0xc, %ah 
.65276: movw %ax, -0xc(%rsp) 
.65281: fld %st(0) 
.65283: fldcw -0xc(%rsp) 
.65287: fistpll -0x18(%rsp) 
.65291: fldcw -0xa(%rsp) 
.65295: movq -0x18(%rsp), %rax 
.65300: movq %rax, -0x18(%rsp) 
.65305: fildll -0x18(%rsp) 
.65309: testq %rax, %rax 
.65312: jns .65320 
.65314: fadds .114568(%rip) 
.65320: testl %edi, %edi 
.65322: jne .65368 
.65324: fxch %st(1) 
.65326: fucomip %st(1) 
.65328: jp .65336 
.65330: je .65370 
.65332: fstp %st(0) 
.65334: jmp .65344 
.65336: fstp %st(0) 
.65338: nopw (%rax, %rax) 
.65344: addq $1, %rax 
.65348: movq %rax, -0x18(%rsp) 
.65353: fildll -0x18(%rsp) 
.65357: js .65424 
.65359: jmp .65370 
.65368: fstp %st(1) 
.65370: ret 
.65376: fnstcw -0xa(%rsp) 
.65380: fsub %st(0), %st(1) 
.65382: fxch %st(1) 
.65384: movzwl -0xa(%rsp), %eax 
.65389: orb $0xc, %ah 
.65392: movw %ax, -0xc(%rsp) 
.65397: fldcw -0xc(%rsp) 
.65401: fistpll -0x18(%rsp) 
.65405: fldcw -0xa(%rsp) 
.65409: movq -0x18(%rsp), %rax 
.65414: btcq $0x3f, %rax 
.65419: jmp .65300 
.65424: fadds .114568(%rip) 
.65430: ret 
