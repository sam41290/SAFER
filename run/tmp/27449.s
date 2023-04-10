.27449: nopl (%rax) 
.27456: movl %edi, %edi 
.27458: leaq .143456(%rip), %rax 
.27465: xorl %r8d, %r8d 
.27468: shlq $4, %rdi 
.27472: addq %rax, %rdi 
.27475: movq (%rdi), %rax 
.27478: testq %rax, %rax 
.27481: je .27505 
.27483: movq 8(%rdi), %rdx 
.27487: cmpq $1, %rax 
.27491: je .27512 
.27493: movl $1, %r8d 
.27499: cmpq $2, %rax 
.27503: je .27528 
.27505: movl %r8d, %eax 
.27508: ret 
.27512: cmpb $0x30, (%rdx) 
.27515: setne %r8b 
.27519: movl %r8d, %eax 
.27522: ret 
.27528: movzbl (%rdx), %eax 
.27531: subl $0x30, %eax 
.27534: jne .27543 
.27536: movzbl 1(%rdx), %eax 
.27540: subl $0x30, %eax 
.27543: testl %eax, %eax 
.27545: setne %r8b 
.27549: movl %r8d, %eax 
.27552: ret 
