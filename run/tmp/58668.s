.58668: nopl (%rax) 
.58672: endbr64 
.58676: pushq %r15 
.58678: pushq %r14 
.58680: pushq %r13 
.58682: pushq %r12 
.58684: movq %rdi, %r12 
.58687: pushq %rbp 
.58688: movq %rsi, %rbp 
.58691: pushq %rbx 
.58692: subq $0x18, %rsp 
.58696: movq %rdx, 8(%rsp) 
.58701: callq .57664 
.58706: movq %rax, %r13 
.58709: movq %rax, %rdi 
.58712: callq .57760 
.58717: subq %r12, %r13 
.58720: movq %rbp, %rdi 
.58723: leaq (%r13, %rax), %r14 
.58728: movq %rax, %rbx 
.58731: callq .18624 
.58736: movq %rax, %r13 
.58739: testq %rbx, %rbx 
.58742: je .58792 
.58744: cmpb $0x2f, -1(%r12, %r14) 
.58750: je .58912 
.58756: xorl %ebx, %ebx 
.58758: movl $0, %r15d 
.58764: cmpb $0x2f, (%rbp) 
.58768: movl $0x2f, %eax 
.58773: cmovel %r15d, %eax 
.58777: setne %bl 
.58780: movb %al, 7(%rsp) 
.58784: jmp .58820 
.58792: xorl %ebx, %ebx 
.58794: movl $0, %r15d 
.58800: cmpb $0x2f, (%rbp) 
.58804: movl $0x2e, %eax 
.58809: cmovnel %r15d, %eax 
.58813: sete %bl 
.58816: movb %al, 7(%rsp) 
.58820: leaq 1(%r14, %r13), %rdi 
.58825: addq %rbx, %rdi 
.58828: callq .18144 
.58833: movq %rax, %r15 
.58836: testq %rax, %rax 
.58839: je .58893 
.58841: movq %rax, %rdi 
.58844: movq %r14, %rdx 
.58847: movq %r12, %rsi 
.58850: callq .19520 
.58855: movzbl 7(%rsp), %ecx 
.58860: leaq (%rax, %rbx), %rdi 
.58864: movb %cl, (%rax) 
.58866: movq 8(%rsp), %rax 
.58871: testq %rax, %rax 
.58874: je .58879 
.58876: movq %rdi, (%rax) 
.58879: movq %r13, %rdx 
.58882: movq %rbp, %rsi 
.58885: callq .19520 
.58890: movb $0, (%rax) 
.58893: addq $0x18, %rsp 
.58897: movq %r15, %rax 
.58900: popq %rbx 
.58901: popq %rbp 
.58902: popq %r12 
.58904: popq %r13 
.58906: popq %r14 
.58908: popq %r15 
.58910: ret 
.58912: movb $0, 7(%rsp) 
.58917: xorl %ebx, %ebx 
.58919: jmp .58820 
