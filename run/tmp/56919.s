.56144: movq 0xd8(%rsp), %rax 
.56152: xorq %fs:0x28, %rax 
.56161: jne .57273 
.56167: addq $0xe8, %rsp 
.56174: movq %r14, %rax 
.56177: popq %rbx 
.56178: popq %rbp 
.56179: popq %r12 
.56181: popq %r13 
.56183: popq %r14 
.56185: popq %r15 
.56187: ret 
.56743: movq 0x18(%rsp), %rdi 
.56748: movl %edx, 8(%rsp) 
.56752: callq .63104 
.56757: movl 8(%rsp), %edx 
.56761: movl %edx, (%r15) 
.56764: xorl %r14d, %r14d 
.56767: jmp .56144 
.56919: nopw (%rax, %rax) 
.56928: movq %r13, %r15 
.56931: movq 0x30(%rsp), %rdi 
.56936: movl %edx, 8(%rsp) 
.56940: callq .18128 
.56945: movq %r14, %rdi 
.56948: callq .18128 
.56953: cmpq $0, 0x18(%rsp) 
.56959: movl 8(%rsp), %edx 
.56963: je .56761 
.56969: jmp .56743 
.57273: hlt 
