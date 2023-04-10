.72081: nopw %cs:(%rax, %rax) 
.72092: nopl (%rax) 
.72096: pushq %r12 
.72098: movq %rdi, %r12 
.72101: pushq %rbp 
.72102: pushq %rbx 
.72103: testq %rdx, %rdx 
.72106: je .72153 
.72108: movq %rsi, %rbp 
.72111: leaq -1(%rdx), %rbx 
.72115: callq .18176 
.72120: nopl (%rax, %rax) 
.72128: movzbl (%rbp, %rbx), %ecx 
.72133: movq (%rax), %rdx 
.72136: movl (%rdx, %rcx, 4), %edx 
.72139: movb %dl, (%r12, %rbx) 
.72143: subq $1, %rbx 
.72147: cmpq $-1, %rbx 
.72151: jne .72128 
.72153: movq %r12, %rax 
.72156: popq %rbx 
.72157: popq %rbp 
.72158: popq %r12 
.72160: ret 
