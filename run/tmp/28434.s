.19664: endbr64 
.19668: bnd jmpq *.143192(%rip) 
.28434: nopw %cs:(%rax, %rax) 
.28445: nopl (%rax) 
.28448: pushq %rbx 
.28449: movq %rdi, %rbx 
.28452: movq (%rdi), %rdi 
.28455: callq .18128 
.28460: movq 8(%rbx), %rdi 
.28464: callq .18128 
.28469: movq 0x10(%rbx), %rdi 
.28473: callq .18128 
.28478: movq 0xb0(%rbx), %rdi 
.28485: leaq .143394(%rip), %rax 
.28492: cmpq %rax, %rdi 
.28495: je .28512 
.28497: popq %rbx 
.28498: jmp .19664 
.28512: popq %rbx 
.28513: ret 
