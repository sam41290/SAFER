.55335: nopw (%rax, %rax) 
.55344: endbr64 
.55348: pushq %r14 
.55350: pushq %r13 
.55352: pushq %r12 
.55354: pushq %rbp 
.55355: pushq %rbx 
.55356: movq (%rsi), %r14 
.55359: testq %r14, %r14 
.55362: je .55417 
.55364: movq %rdi, %r12 
.55367: movq %rcx, %r13 
.55370: leaq 8(%rsi), %rbx 
.55374: movq %rdx, %rbp 
.55377: jmp .55399 
.55384: movq (%rbx), %r14 
.55387: addq %r13, %rbp 
.55390: addq $8, %rbx 
.55394: testq %r14, %r14 
.55397: je .55417 
.55399: movq %r13, %rdx 
.55402: movq %rbp, %rsi 
.55405: movq %r12, %rdi 
.55408: callq .18992 
.55413: testl %eax, %eax 
.55415: jne .55384 
.55417: popq %rbx 
.55418: movq %r14, %rax 
.55421: popq %rbp 
.55422: popq %r12 
.55424: popq %r13 
.55426: popq %r14 
.55428: ret 
