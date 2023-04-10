.62039: nopw (%rax, %rax) 
.62048: endbr64 
.62052: pushq %r12 
.62054: movq %rdi, %r12 
.62057: pushq %rbp 
.62058: movq %rsi, %rbp 
.62061: pushq %rbx 
.62062: callq .60368 
.62067: movq (%rax), %rsi 
.62070: testq %rsi, %rsi 
.62073: je .62109 
.62075: movq %rax, %rbx 
.62078: jmp .62083 
.62080: movq (%rbx), %rsi 
.62083: cmpq %rbp, %rsi 
.62086: je .62123 
.62088: movq %rbp, %rdi 
.62091: callq *0x38(%r12) 
.62096: testb %al, %al 
.62098: jne .62120 
.62100: movq 8(%rbx), %rbx 
.62104: testq %rbx, %rbx 
.62107: jne .62080 
.62109: popq %rbx 
.62110: xorl %eax, %eax 
.62112: popq %rbp 
.62113: popq %r12 
.62115: ret 
.62120: movq (%rbx), %rbp 
.62123: movq %rbp, %rax 
.62126: popq %rbx 
.62127: popq %rbp 
.62128: popq %r12 
.62130: ret 
