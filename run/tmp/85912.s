.19932: hlt 
.85760: endbr64 
.85764: subq $0x48, %rsp 
.85768: movdqa .148768(%rip), %xmm0 
.85776: movdqa .148784(%rip), %xmm1 
.85784: movq %fs:0x28, %rax 
.85793: movq %rax, 0x38(%rsp) 
.85798: xorl %eax, %eax 
.85800: movdqa .148800(%rip), %xmm2 
.85808: movq .148816(%rip), %rax 
.85815: movaps %xmm0, (%rsp) 
.85819: movq %rax, 0x30(%rsp) 
.85824: movl $0xa, (%rsp) 
.85831: movaps %xmm1, 0x10(%rsp) 
.85836: movaps %xmm2, 0x20(%rsp) 
.85841: testq %rsi, %rsi 
.85844: je .19932 
.85850: testq %rdx, %rdx 
.85853: je .19932 
.85859: movq %rcx, %r9 
.85862: movq %rsi, 0x28(%rsp) 
.85867: movq %rsp, %rcx 
.85870: movq %rdx, 0x30(%rsp) 
.85875: movq %r9, %rsi 
.85878: movq %r8, %rdx 
.85881: callq .83648 
.85886: movq 0x38(%rsp), %rcx 
.85891: xorq %fs:0x28, %rcx 
.85900: jne .85907 
.85902: addq $0x48, %rsp 
.85906: ret 
.85907: hlt 
.85912: nopl (%rax, %rax) 
.85920: endbr64 
.85924: movq $-1, %r8 
.85931: jmp .85760 
