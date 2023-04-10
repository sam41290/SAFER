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
.36853: nopl (%rax) 
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
.36928: hlt 
