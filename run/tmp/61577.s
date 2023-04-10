.61577: nopl (%rax) 
.61584: endbr64 
.61588: movq (%rdi), %rcx 
.61591: movq 8(%rdi), %rsi 
.61595: xorl %edx, %edx 
.61597: xorl %r8d, %r8d 
.61600: cmpq %rsi, %rcx 
.61603: jb .61625 
.61605: jmp .61670 
.61616: addq $0x10, %rcx 
.61620: cmpq %rsi, %rcx 
.61623: jae .61670 
.61625: cmpq $0, (%rcx) 
.61629: je .61616 
.61631: movq 8(%rcx), %rax 
.61635: addq $1, %r8 
.61639: addq $1, %rdx 
.61643: testq %rax, %rax 
.61646: je .61616 
.61648: movq 8(%rax), %rax 
.61652: addq $1, %rdx 
.61656: testq %rax, %rax 
.61659: jne .61648 
.61661: addq $0x10, %rcx 
.61665: cmpq %rsi, %rcx 
.61668: jb .61625 
.61670: xorl %eax, %eax 
.61672: cmpq %r8, 0x18(%rdi) 
.61676: je .61679 
.61678: ret 
.61679: cmpq %rdx, 0x20(%rdi) 
.61683: sete %al 
.61686: ret 
