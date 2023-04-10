.84734: nop 
.84736: endbr64 
.84740: movl .143928(%rip), %eax 
.84746: pushq %r12 
.84748: movq .143936(%rip), %r12 
.84755: pushq %rbp 
.84756: pushq %rbx 
.84757: cmpl $1, %eax 
.84760: jle .84801 
.84762: subl $2, %eax 
.84765: leaq 0x18(%r12), %rbx 
.84770: shlq $4, %rax 
.84774: leaq 0x28(%r12, %rax), %rbp 
.84779: nopl (%rax, %rax) 
.84784: movq (%rbx), %rdi 
.84787: addq $0x10, %rbx 
.84791: callq .18128 
.84796: cmpq %rbp, %rbx 
.84799: jne .84784 
.84801: movq 8(%r12), %rdi 
.84806: leaq .148512(%rip), %rbx 
.84813: cmpq %rbx, %rdi 
.84816: je .84841 
.84818: callq .18128 
.84823: movq %rbx, .143960(%rip) 
.84830: movq $0x100, .143952(%rip) 
.84841: leaq .143952(%rip), %rbx 
.84848: cmpq %rbx, %r12 
.84851: je .84868 
.84853: movq %r12, %rdi 
.84856: callq .18128 
.84861: movq %rbx, .143936(%rip) 
.84868: movl $1, .143928(%rip) 
.84878: popq %rbx 
.84879: popq %rbp 
.84880: popq %r12 
.84882: ret 
