.70652: nopl (%rax) 
.70656: endbr64 
.70660: pushq %r15 
.70662: pushq %r14 
.70664: movq %rdi, %r14 
.70667: pushq %r13 
.70669: movl %edx, %r13d 
.70672: pushq %r12 
.70674: xorl %r12d, %r12d 
.70677: pushq %rbp 
.70678: pushq %rbx 
.70679: movq %rsi, %rbx 
.70682: subq $0x18, %rsp 
.70686: movq (%rsi), %rax 
.70689: movl %ecx, 0xc(%rsp) 
.70693: movq %rax, (%rsp) 
.70697: nopl (%rax) 
.70704: leaq 1(%rax), %rbp 
.70708: movq %r12, %rdi 
.70711: movq %r12, %r15 
.70714: movq %rbp, %rsi 
.70717: callq .19424 
.70722: movq %rax, %r12 
.70725: testq %rax, %rax 
.70728: je .70813 
.70730: movq (%rsp), %rax 
.70734: movl 0xc(%rsp), %r9d 
.70739: movl %r13d, %r8d 
.70742: movq %rbx, %rcx 
.70745: movq %rbp, %rdx 
.70748: movq %r12, %rsi 
.70751: movq %r14, %rdi 
.70754: movq %rax, (%rbx) 
.70757: callq .69664 
.70762: cmpq $-1, %rax 
.70766: je .70800 
.70768: cmpq %rax, %rbp 
.70771: jbe .70704 
.70773: addq $0x18, %rsp 
.70777: movq %r12, %rax 
.70780: popq %rbx 
.70781: popq %rbp 
.70782: popq %r12 
.70784: popq %r13 
.70786: popq %r14 
.70788: popq %r15 
.70790: ret 
.70800: movq %r12, %rdi 
.70803: xorl %r12d, %r12d 
.70806: callq .18128 
.70811: jmp .70773 
.70813: movq %r15, %rdi 
.70816: callq .18128 
.70821: jmp .70773 
