.36520: nopl (%rax, %rax) 
.36528: pushq %r12 
.36530: movq %rsi, %r12 
.36533: pushq %rbx 
.36534: movq %rdi, %rbx 
.36537: subq $0x2a8, %rsp 
.36544: movq %fs:0x28, %rax 
.36553: movq %rax, 0x298(%rsp) 
.36561: xorl %eax, %eax 
.36563: callq .33136 
.36568: cmpb $0, .148220(%rip) 
.36575: je .36642 
.36577: cmpb $0, 0xb8(%rbx) 
.36584: leaq .104418(%rip), %rcx 
.36591: je .36606 
.36593: movq 0x20(%rbx), %rdi 
.36597: testq %rdi, %rdi 
.36600: jne .36912 
.36606: xorl %edx, %edx 
.36608: cmpl $4, .148280(%rip) 
.36615: je .36623 
.36617: movl .148320(%rip), %edx 
.36623: leaq .104463(%rip), %rsi 
.36630: movl $1, %edi 
.36635: xorl %eax, %eax 
.36637: callq .19472 
.36642: cmpb $0, .148268(%rip) 
.36649: je .36707 
.36651: cmpb $0, 0xb8(%rbx) 
.36658: leaq .104418(%rip), %rcx 
.36665: jne .36856 
.36671: xorl %edx, %edx 
.36673: cmpl $4, .148280(%rip) 
.36680: je .36688 
.36682: movl .148316(%rip), %edx 
.36688: leaq .104463(%rip), %rsi 
.36695: movl $1, %edi 
.36700: xorl %eax, %eax 
.36702: callq .19472 
.36707: cmpb $0, .148325(%rip) 
.36714: je .36759 
.36716: xorl %edx, %edx 
.36718: cmpl $4, .148280(%rip) 
.36725: movq 0xb0(%rbx), %rcx 
.36732: je .36740 
.36734: movl .148308(%rip), %edx 
.36740: leaq .104463(%rip), %rsi 
.36747: movl $1, %edi 
.36752: xorl %eax, %eax 
.36754: callq .19472 
.36759: movq %r12, %rcx 
.36762: xorl %edx, %edx 
.36764: xorl %esi, %esi 
.36766: movq %rbx, %rdi 
.36769: callq .35424 
.36774: movq %rax, %r12 
.36777: movl .148244(%rip), %eax 
.36783: testl %eax, %eax 
.36785: jne .36824 
.36787: movq 0x298(%rsp), %rax 
.36795: xorq %fs:0x28, %rax 
.36804: jne .36928 
.36806: addq $0x2a8, %rsp 
.36813: movq %r12, %rax 
.36816: popq %rbx 
.36817: popq %r12 
.36819: ret 
.36824: movl 0xa8(%rbx), %edx 
.36830: movl 0x30(%rbx), %esi 
.36833: movzbl 0xb8(%rbx), %edi 
.36840: callq .31536 
.36845: movzbl %al, %eax 
.36848: addq %rax, %r12 
.36851: jmp .36787 
.36856: movl .148264(%rip), %edx 
.36862: movq 0x58(%rbx), %rdi 
.36866: movl $0x200, %ecx 
.36871: movq %rsp, %rsi 
.36874: movq .148256(%rip), %r8 
.36881: callq .65440 
.36886: xorl %edx, %edx 
.36888: cmpl $4, .148280(%rip) 
.36895: movq %rax, %rcx 
.36898: jne .36682 
.36904: jmp .36688 
.36912: movq %rsp, %rsi 
.36915: callq .69568 
.36920: movq %rax, %rcx 
.36923: jmp .36606 
.36928: hlt 
