.93417: nopl (%rax) 
.93424: pushq %r13 
.93426: pushq %r12 
.93428: pushq %rbp 
.93429: movq %rdi, %rbp 
.93432: pushq %rbx 
.93433: subq $8, %rsp 
.93437: callq .18272 
.93442: cmpb $0, 8(%rbp) 
.93446: leaq 9(%rbp), %rdi 
.93450: movl (%rax), %r12d 
.93453: movq %rax, %rbx 
.93456: jne .93460 
.93458: xorl %edi, %edi 
.93460: callq .93328 
.93465: testl %eax, %eax 
.93467: je .93504 
.93469: movl (%rbx), %r12d 
.93472: xorl %r13d, %r13d 
.93475: movq %rbp, %rdi 
.93478: callq .93376 
.93483: movl %r12d, (%rbx) 
.93486: addq $8, %rsp 
.93490: movl %r13d, %eax 
.93493: popq %rbx 
.93494: popq %rbp 
.93495: popq %r12 
.93497: popq %r13 
.93499: ret 
.93504: callq .19216 
.93509: movl $1, %r13d 
.93515: jmp .93475 
