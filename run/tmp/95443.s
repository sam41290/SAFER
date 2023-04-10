.95443: nopw %cs:(%rax, %rax) 
.95453: nopl (%rax) 
.95456: endbr64 
.95460: pushq %r15 
.95462: leaq .139280(%rip), %r15 
.95469: pushq %r14 
.95471: movq %rdx, %r14 
.95474: pushq %r13 
.95476: movq %rsi, %r13 
.95479: pushq %r12 
.95481: movl %edi, %r12d 
.95484: pushq %rbp 
.95485: leaq .139288(%rip), %rbp 
.95492: pushq %rbx 
.95493: subq %r15, %rbp 
.95496: subq $8, %rsp 
.95500: callq .16384 
.95505: sarq $3, %rbp 
.95509: je .95542 
.95511: xorl %ebx, %ebx 
.95513: nopl (%rax) 
.95520: movq %r14, %rdx 
.95523: movq %r13, %rsi 
.95526: movl %r12d, %edi 
.95529: callq *(%r15, %rbx, 8) 
.95533: addq $1, %rbx 
.95537: cmpq %rbx, %rbp 
.95540: jne .95520 
.95542: addq $8, %rsp 
.95546: popq %rbx 
.95547: popq %rbp 
.95548: popq %r12 
.95550: popq %r13 
.95552: popq %r14 
.95554: popq %r15 
.95556: ret 
