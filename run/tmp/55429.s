.55429: nopw %cs:(%rax, %rax) 
.55439: nop 
.55440: endbr64 
.55444: cmpq %rsi, %rdi 
.55447: je .55544 
.55449: testq %rdx, %rdx 
.55452: je .55544 
.55454: leaq -1(%rdx), %r10 
.55458: xorl %edx, %edx 
.55460: jmp .55485 
.55472: testl %eax, %eax 
.55474: je .55537 
.55476: addq $1, %rdx 
.55480: cmpb %cl, %r8b 
.55483: jne .55537 
.55485: movzbl (%rdi, %rdx), %eax 
.55489: leal -0x41(%rax), %ecx 
.55492: movl %eax, %r8d 
.55495: cmpl $0x19, %ecx 
.55498: ja .55507 
.55500: addl $0x20, %eax 
.55503: addl $0x20, %r8d 
.55507: movzbl (%rsi, %rdx), %r9d 
.55512: leal -0x41(%r9), %r11d 
.55516: movl %r9d, %ecx 
.55519: cmpl $0x19, %r11d 
.55523: ja .55532 
.55525: addl $0x20, %r9d 
.55529: addl $0x20, %ecx 
.55532: cmpq %r10, %rdx 
.55535: jne .55472 
.55537: subl %r9d, %eax 
.55540: ret 
.55544: xorl %eax, %eax 
.55546: ret 
