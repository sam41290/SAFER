.19408: endbr64 
.19412: bnd jmpq *.143064(%rip) 
.32654: nop 
.32656: cmpq $0, .143496(%rip) 
.32664: je .32688 
.32666: leaq .143496(%rip), %rsi 
.32673: leaq -8(%rsi), %rdi 
.32677: jmp .32752 
.32688: leaq .143464(%rip), %rsi 
.32695: subq $8, %rsp 
.32699: leaq -8(%rsi), %rdi 
.32703: callq .32752 
.32708: leaq .143512(%rip), %rsi 
.32715: leaq -8(%rsi), %rdi 
.32719: callq .32752 
.32724: leaq .143480(%rip), %rsi 
.32731: addq $8, %rsp 
.32735: leaq -8(%rsi), %rdi 
.32739: jmp .32752 
.32752: pushq %rbp 
.32753: movq %rdi, %rbp 
.32756: pushq %rbx 
.32757: movq %rsi, %rbx 
.32760: subq $8, %rsp 
.32764: cmpb $0, .148240(%rip) 
.32771: je .32808 
.32773: movq (%rbp), %rsi 
.32777: movq (%rbx), %rdi 
.32780: movl $1, %edx 
.32785: movq .144008(%rip), %rcx 
.32792: addq $8, %rsp 
.32796: popq %rbx 
.32797: popq %rbp 
.32798: jmp .19408 
.32808: movl $1, %edi 
.32813: movb $1, .148240(%rip) 
.32820: callq .19248 
.32825: testl %eax, %eax 
.32827: jns .32840 
.32829: callq .32656 
.32834: jmp .32773 
.32840: movl $1, %edi 
.32845: callq .32192 
.32850: callq .32656 
.32855: jmp .32773 
