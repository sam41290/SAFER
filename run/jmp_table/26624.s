.26624: leaq .143976(%rip), %rdi 
.26631: leaq .143976(%rip), %rax 
.26638: cmpq %rdi, %rax 
.26641: je .26664 
.26643: movq .143304(%rip), %rax 
.26650: testq %rax, %rax 
.26653: je .26664 
.26655: jmpq *%rax 
.26664: ret 
