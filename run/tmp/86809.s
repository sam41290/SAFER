.19937: hlt 
.86672: xorl %edi, %edi 
.86674: movl $5, %edx 
.86679: leaq .117115(%rip), %rsi 
.86686: callq .18592 
.86691: movl $0x7e2, %r8d 
.86697: movl $1, %esi 
.86702: movq %rbp, %rdi 
.86705: movq %rax, %rcx 
.86708: leaq .117920(%rip), %rdx 
.86715: xorl %eax, %eax 
.86717: callq .19744 
.86722: xorl %edi, %edi 
.86724: movl $5, %edx 
.86729: leaq .117256(%rip), %rsi 
.86736: callq .18592 
.86741: movq %rbp, %rsi 
.86744: movq %rax, %rdi 
.86747: callq .19024 
.86752: cmpq $9, %r12 
.86756: ja .87620 
.86762: leaq .117860(%rip), %rdx 
.86769: movslq (%rdx, %r12, 4), %rax 
.86773: addq %rdx, %rax 
.86776: jmpq *%rax 
.86809: jmp .86672 
.86893: movq 0x28(%rsp), %r10 
.86898: movq %rbp, %rdi 
.86901: movl $1, %esi 
.86906: xorl %eax, %eax 
.86908: pushq %r10 
.86910: movq 0x28(%rsp), %r9 
.86915: pushq %r9 
.86917: movq 0x28(%rsp), %r8 
.86922: movq %r14, %r9 
.86925: pushq %r8 
.86927: movq 0x28(%rsp), %rcx 
.86932: movq %r13, %r8 
.86935: pushq %rcx 
.86936: movq %r12, %rcx 
.86939: pushq %r15 
.86941: callq .19744 
.86946: addq $0x30, %rsp 
.86950: addq $0x38, %rsp 
.86954: popq %rbx 
.86955: popq %rbp 
.86956: popq %r12 
.86958: popq %r13 
.86960: popq %r14 
.86962: popq %r15 
.86964: ret 
.87040: xorl %edi, %edi 
.87042: callq .18592 
.87047: movq 0x28(%rsp), %r11 
.87052: movq %rax, %rdx 
.87055: pushq %r11 
.87057: jmp .86893 
.87620: movq 0x40(%rbx), %r11 
.87624: movq 0x38(%rbx), %r10 
.87628: movl $5, %edx 
.87633: leaq .117728(%rip), %rsi 
.87640: movq 0x30(%rbx), %r9 
.87644: movq 0x28(%rbx), %r8 
.87648: movq 0x20(%rbx), %rcx 
.87652: movq 0x18(%rbx), %r15 
.87656: movq %r11, 0x28(%rsp) 
.87661: movq 0x10(%rbx), %r14 
.87665: movq 8(%rbx), %r13 
.87669: movq %r10, 0x20(%rsp) 
.87674: movq %r9, 0x18(%rsp) 
.87679: movq (%rbx), %r12 
.87682: movq %r8, 0x10(%rsp) 
.87687: movq %rcx, 8(%rsp) 
.87692: jmp .87040 
