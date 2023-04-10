.72016: pushq %r12 
.72018: movq %rdi, %r12 
.72021: pushq %rbp 
.72022: pushq %rbx 
.72023: testq %rdx, %rdx 
.72026: je .72073 
.72028: movq %rsi, %rbp 
.72031: leaq -1(%rdx), %rbx 
.72035: callq .19824 
.72040: nopl (%rax, %rax) 
.72048: movzbl (%rbp, %rbx), %ecx 
.72053: movq (%rax), %rdx 
.72056: movl (%rdx, %rcx, 4), %edx 
.72059: movb %dl, (%r12, %rbx) 
.72063: subq $1, %rbx 
.72067: cmpq $-1, %rbx 
.72071: jne .72048 
.72073: movq %r12, %rax 
.72076: popq %rbx 
.72077: popq %rbp 
.72078: popq %r12 
.72080: ret 
