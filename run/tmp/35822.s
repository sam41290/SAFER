.35529: addq $0x18, %rsp 
.35533: movq %r12, %rax 
.35536: popq %rbx 
.35537: popq %rbp 
.35538: popq %r12 
.35540: popq %r13 
.35542: popq %r14 
.35544: popq %r15 
.35546: ret 
.35822: movq %rax, %r12 
.35825: callq .32912 
.35830: callq .32656 
.35835: movq .148144(%rip), %rcx 
.35842: popq %rax 
.35843: popq %rdx 
.35844: testq %rcx, %rcx 
.35847: je .35529 
.35853: movq %rbp, %rax 
.35856: xorl %edx, %edx 
.35858: divq %rcx 
.35861: xorl %edx, %edx 
.35863: movq %rax, %rsi 
.35866: leaq -1(%r12, %rbp), %rax 
.35871: divq %rcx 
.35874: cmpq %rax, %rsi 
.35877: je .35529 
.35883: leaq .143832(%rip), %rsi 
.35890: leaq -8(%rsi), %rdi 
.35894: callq .32752 
.35899: jmp .35529 
