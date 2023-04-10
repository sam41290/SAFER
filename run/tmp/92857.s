.92857: nopl (%rax) 
.92864: endbr64 
.92868: pushq %r14 
.92870: xorl %eax, %eax 
.92872: pushq %r13 
.92874: pushq %r12 
.92876: pushq %rbp 
.92877: pushq %rbx 
.92878: movq 0x18(%rdi), %r14 
.92882: subq 0x10(%rdi), %r14 
.92886: movq 8(%rdi), %rbp 
.92890: addq %r14, %rsi 
.92893: movq %r14, %rdx 
.92896: setb %al 
.92899: addq 0x30(%rdi), %rsi 
.92903: setb %cl 
.92906: shrq $3, %rdx 
.92910: cmpq %rsi, (%rdi) 
.92913: leaq 0x64(%rsi, %rdx), %r12 
.92918: cmovaeq (%rdi), %rsi 
.92922: cmpq %r12, %rsi 
.92925: cmovaeq %rsi, %r12 
.92929: testq %rax, %rax 
.92932: jne .93093 
.92938: movzbl %cl, %ecx 
.92941: testq %rcx, %rcx 
.92944: jne .93093 
.92950: movq %r12, %rsi 
.92953: movq %rdi, %rbx 
.92956: callq .92592 
.92961: movq %rax, %r13 
.92964: testq %rax, %rax 
.92967: je .93093 
.92969: leaq (%rax, %r12), %rsi 
.92973: movq %rax, 8(%rbx) 
.92977: movq %r14, %rdx 
.92980: movq %rbp, 8(%rax) 
.92984: movq %rsi, 0x20(%rbx) 
.92988: movq %rsi, (%rax) 
.92991: movq 0x30(%rbx), %rax 
.92995: movq 0x10(%rbx), %rsi 
.92999: leaq 0x10(%r13, %rax), %r12 
.93004: notq %rax 
.93007: andq %rax, %r12 
.93010: movq %r12, %rdi 
.93013: callq .19168 
.93018: testb $2, 0x50(%rbx) 
.93022: jne .93045 
.93024: movq 0x30(%rbx), %rax 
.93028: leaq 0x10(%rbp, %rax), %rdx 
.93033: notq %rax 
.93036: andq %rdx, %rax 
.93039: cmpq %rax, 0x10(%rbx) 
.93043: je .93072 
.93045: addq %r12, %r14 
.93048: andb $0xfd, 0x50(%rbx) 
.93052: movq %r12, 0x10(%rbx) 
.93056: movq %r14, 0x18(%rbx) 
.93060: popq %rbx 
.93061: popq %rbp 
.93062: popq %r12 
.93064: popq %r13 
.93066: popq %r14 
.93068: ret 
.93072: movq 8(%rbp), %rax 
.93076: movq %rbp, %rsi 
.93079: movq %rbx, %rdi 
.93082: movq %rax, 8(%r13) 
.93086: callq .92624 
.93091: jmp .93045 
.93093: callq *.143968(%rip) 
.93099: nopl (%rax, %rax) 
.93104: endbr64 
.93108: movq 8(%rdi), %rax 
.93112: testq %rax, %rax 
.93115: je .93158 
.93117: nopl (%rax) 
.93120: cmpq %rax, %rsi 
.93123: jbe .93130 
.93125: cmpq %rsi, (%rax) 
.93128: jae .93152 
.93130: movq 8(%rax), %rax 
.93134: testq %rax, %rax 
.93137: jne .93120 
.93139: xorl %eax, %eax 
.93141: ret 
.93152: movl $1, %eax 
.93157: ret 
.93158: ret 
