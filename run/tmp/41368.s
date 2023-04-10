.41368: nopl (%rax, %rax) 
.41376: cmpl $4, .148280(%rip) 
.41383: ja .42282 
.41389: pushq %r15 
.41391: leaq .98628(%rip), %rdx 
.41398: pushq %r14 
.41400: pushq %r13 
.41402: pushq %r12 
.41404: pushq %rbp 
.41405: pushq %rbx 
.41406: subq $0x28, %rsp 
.41410: movl .148280(%rip), %eax 
.41416: movslq (%rdx, %rax, 4), %rax 
.41420: addq %rdx, %rax 
.41423: jmpq *%rax 
.41696: xorl %ebx, %ebx 
.41698: cmpq $0, .148400(%rip) 
.41706: je .42119 
.41712: callq .33136 
.41717: movq .148384(%rip), %rax 
.41724: movq (%rax, %rbx, 8), %rdi 
.41728: callq .36944 
.41733: movq .144008(%rip), %rdi 
.41740: movq 0x28(%rdi), %rax 
.41744: cmpq 0x30(%rdi), %rax 
.41748: jae .42176 
.41754: leaq 1(%rax), %rdx 
.41758: movq %rdx, 0x28(%rdi) 
.41762: movb $0xa, (%rax) 
.41765: addq $1, .147960(%rip) 
.41773: addq $1, %rbx 
.41777: cmpq %rbx, .148400(%rip) 
.41784: ja .41712 
.41786: jmp .42119 
.42119: addq $0x28, %rsp 
.42123: popq %rbx 
.42124: popq %rbp 
.42125: popq %r12 
.42127: popq %r13 
.42129: popq %r14 
.42131: popq %r15 
.42133: ret 
.42176: movl $0xa, %esi 
.42181: callq .18768 
.42186: jmp .41765 
.42282: ret 
