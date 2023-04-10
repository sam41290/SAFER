.19568: endbr64 
.19572: bnd jmpq *.143144(%rip) 
.95320: nopl (%rax, %rax) 
.95328: endbr64 
.95332: pushq %rbp 
.95333: movq %rdi, %rbp 
.95336: subq $0x10, %rsp 
.95340: movq 8(%rdi), %rax 
.95344: cmpq %rax, 0x10(%rdi) 
.95348: je .95368 
.95350: addq $0x10, %rsp 
.95354: movq %rbp, %rdi 
.95357: popq %rbp 
.95358: jmp .19568 
.95368: movq 0x20(%rdi), %rax 
.95372: cmpq %rax, 0x28(%rdi) 
.95376: jne .95350 
.95378: cmpq $0, 0x48(%rdi) 
.95383: jne .95350 
.95385: movl %edx, 0xc(%rsp) 
.95389: movq %rsi, (%rsp) 
.95393: callq .19232 
.95398: movl 0xc(%rsp), %edx 
.95402: movq (%rsp), %rsi 
.95406: movl %eax, %edi 
.95408: callq .18832 
.95413: cmpq $-1, %rax 
.95417: je .95438 
.95419: andl $0xffffffef, (%rbp) 
.95423: movq %rax, 0x90(%rbp) 
.95430: xorl %eax, %eax 
.95432: addq $0x10, %rsp 
.95436: popq %rbp 
.95437: ret 
.95438: orl $0xffffffff, %eax 
.95441: jmp .95432 
