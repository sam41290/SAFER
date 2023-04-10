.27553: nopw %cs:(%rax, %rax) 
.27564: nopl (%rax) 
.27568: subq $0x18, %rsp 
.27572: xorl %edx, %edx 
.27574: leaq .104446(%rip), %r8 
.27581: xorl %esi, %esi 
.27583: movq %fs:0x28, %rax 
.27592: movq %rax, 8(%rsp) 
.27597: xorl %eax, %eax 
.27599: movq %rsp, %rcx 
.27602: callq .90944 
.27607: testl %eax, %eax 
.27609: je .27664 
.27611: cmpl $1, %eax 
.27614: jne .27656 
.27616: movq $-1, .148144(%rip) 
.27627: movl $1, %eax 
.27632: movq 8(%rsp), %rdx 
.27637: xorq %fs:0x28, %rdx 
.27646: jne .27682 
.27648: addq $0x18, %rsp 
.27652: ret 
.27656: xorl %eax, %eax 
.27658: jmp .27632 
.27664: movq (%rsp), %rax 
.27668: movq %rax, .148144(%rip) 
.27675: movl $1, %eax 
.27680: jmp .27632 
.27682: hlt 
