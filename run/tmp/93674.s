.93674: nopw (%rax, %rax) 
.93680: pushq %r15 
.93682: pushq %r14 
.93684: pushq %r13 
.93686: pushq %r12 
.93688: pushq %rbp 
.93689: pushq %rbx 
.93690: subq $8, %rsp 
.93694: movq 0x30(%rsi), %r12 
.93698: testq %r12, %r12 
.93701: je .93872 
.93707: movq %rdi, %rbp 
.93710: movq %rsi, %r13 
.93713: cmpq %r12, %rsi 
.93716: ja .93732 
.93718: leaq 0x38(%rsi), %rdx 
.93722: movl $1, %eax 
.93727: cmpq %rdx, %r12 
.93730: jb .93841 
.93732: cmpb $0, (%r12) 
.93737: leaq 9(%rbp), %rbx 
.93741: je .93856 
.93743: nop 
.93744: movq %r12, %rsi 
.93747: movq %rbx, %rdi 
.93750: callq .19072 
.93755: testl %eax, %eax 
.93757: je .93832 
.93759: cmpb $0, (%rbx) 
.93762: jne .93779 
.93764: leaq 9(%rbp), %r14 
.93768: cmpq %rbx, %r14 
.93771: jne .93896 
.93773: cmpb $0, 8(%rbp) 
.93777: je .93896 
.93779: movq %rbx, %rdi 
.93782: callq .18624 
.93787: leaq 1(%rbx, %rax), %rbx 
.93792: cmpb $0, (%rbx) 
.93795: jne .93744 
.93797: movq (%rbp), %rax 
.93801: testq %rax, %rax 
.93804: je .93744 
.93806: leaq 9(%rax), %rbx 
.93810: movq %r12, %rsi 
.93813: movq %rax, %rbp 
.93816: movq %rbx, %rdi 
.93819: callq .19072 
.93824: testl %eax, %eax 
.93826: jne .93759 
.93828: nopl (%rax) 
.93832: movq %rbx, 0x30(%r13) 
.93836: movl $1, %eax 
.93841: addq $8, %rsp 
.93845: popq %rbx 
.93846: popq %rbp 
.93847: popq %r12 
.93849: popq %r13 
.93851: popq %r14 
.93853: popq %r15 
.93855: ret 
.93856: leaq .104446(%rip), %rbx 
.93863: jmp .93832 
.93872: addq $8, %rsp 
.93876: movl $1, %eax 
.93881: popq %rbx 
.93882: popq %rbp 
.93883: popq %r12 
.93885: popq %r13 
.93887: popq %r14 
.93889: popq %r15 
.93891: ret 
.93896: movq %r12, %rdi 
.93899: callq .18624 
.93904: movq %rax, %r15 
.93907: leaq 1(%rax), %rdx 
.93911: movq %rbx, %rax 
.93914: subq %r14, %rax 
.93917: movq %rax, %rcx 
.93920: notq %rcx 
.93923: cmpq %rdx, %rcx 
.93926: jb .93960 
.93928: addq %rdx, %rax 
.93931: cmpq $0x76, %rax 
.93935: ja .93984 
.93937: movq %r12, %rsi 
.93940: movq %rbx, %rdi 
.93943: callq .19168 
.93948: movb $0, 1(%rbx, %r15) 
.93954: jmp .93832 
.93960: callq .18272 
.93965: movl $0xc, (%rax) 
.93971: xorl %eax, %eax 
.93973: jmp .93841 
.93984: movq %r12, %rdi 
.93987: callq .93520 
.93992: movq %rax, (%rbp) 
.93996: testq %rax, %rax 
.93999: je .94014 
.94001: movb $0, 8(%rax) 
.94005: leaq 9(%rax), %rbx 
.94009: jmp .93832 
.94014: xorl %eax, %eax 
.94016: jmp .93841 
