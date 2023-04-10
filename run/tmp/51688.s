.19360: endbr64 
.19364: bnd jmpq *.143040(%rip) 
.29456: pushq %r12 
.29458: movq %rsi, %r12 
.29461: pushq %rbp 
.29462: movq %rdi, %rbp 
.29465: subq $8, %rsp 
.29469: callq .18272 
.29474: movq %r12, %rsi 
.29477: movq %rbp, %rdi 
.29480: movl $0, (%rax) 
.29486: addq $8, %rsp 
.29490: popq %rbp 
.29491: popq %r12 
.29493: jmp .19360 
.51688: nopl (%rax, %rax) 
.51696: endbr64 
.51700: pushq %r12 
.51702: pushq %rbp 
.51703: movq %rdi, %rbp 
.51706: pushq %rbx 
.51707: movl 0xa8(%rdi), %eax 
.51713: movq %rsi, %rbx 
.51716: movl 0xa8(%rsi), %ecx 
.51722: cmpl $3, %eax 
.51725: sete %dl 
.51728: cmpl $9, %eax 
.51731: sete %al 
.51734: orl %eax, %edx 
.51736: cmpl $3, %ecx 
.51739: sete %al 
.51742: cmpl $9, %ecx 
.51745: sete %cl 
.51748: orb %cl, %al 
.51750: jne .51776 
.51752: testb %dl, %dl 
.51754: jne .51872 
.51756: movl $1, %r8d 
.51762: testb %al, %al 
.51764: je .51780 
.51766: popq %rbx 
.51767: movl %r8d, %eax 
.51770: popq %rbp 
.51771: popq %r12 
.51773: ret 
.51776: testb %dl, %dl 
.51778: je .51756 
.51780: movq (%rbx), %rdi 
.51783: movl $0x2e, %esi 
.51788: callq .18784 
.51793: movq (%rbp), %rdi 
.51797: movl $0x2e, %esi 
.51802: movq %rax, %r12 
.51805: callq .18784 
.51810: movq %rax, %rsi 
.51813: leaq .104446(%rip), %rax 
.51820: testq %rsi, %rsi 
.51823: cmoveq %rax, %rsi 
.51827: testq %r12, %r12 
.51830: cmoveq %rax, %r12 
.51834: movq %r12, %rdi 
.51837: callq .29456 
.51842: movl %eax, %r8d 
.51845: testl %eax, %eax 
.51847: jne .51766 
.51849: movq (%rbp), %rsi 
.51853: movq (%rbx), %rdi 
.51856: popq %rbx 
.51857: popq %rbp 
.51858: popq %r12 
.51860: jmp .29456 
.51872: movl $0xffffffff, %r8d 
.51878: jmp .51766 
