.61481: nopl (%rax) 
.61488: endbr64 
.61492: movq (%rdi), %rcx 
.61495: movq 8(%rdi), %rsi 
.61499: xorl %r8d, %r8d 
.61502: cmpq %rsi, %rcx 
.61505: jb .61521 
.61507: jmp .61573 
.61512: addq $0x10, %rcx 
.61516: cmpq %rsi, %rcx 
.61519: jae .61573 
.61521: cmpq $0, (%rcx) 
.61525: je .61512 
.61527: movq 8(%rcx), %rax 
.61531: movl $1, %edx 
.61536: testq %rax, %rax 
.61539: je .61557 
.61541: nopl (%rax) 
.61544: movq 8(%rax), %rax 
.61548: addq $1, %rdx 
.61552: testq %rax, %rax 
.61555: jne .61544 
.61557: cmpq %rdx, %r8 
.61560: cmovbq %rdx, %r8 
.61564: addq $0x10, %rcx 
.61568: cmpq %rsi, %rcx 
.61571: jb .61521 
.61573: movq %r8, %rax 
.61576: ret 
