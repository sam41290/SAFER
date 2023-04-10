.68188: movq 8(%rsp), %rcx 
.68193: xorq %fs:0x28, %rcx 
.68202: jne .68539 
.68208: addq $0x18, %rsp 
.68212: popq %rbx 
.68213: popq %rbp 
.68214: popq %r12 
.68216: popq %r13 
.68218: ret 
.68219: nopl (%rax, %rax) 
.68224: xorl %edx, %edx 
.68226: movq %rsp, %rsi 
.68229: leaq .114622(%rip), %r8 
.68236: movq %rbp, %rcx 
.68239: movq %rbx, %rdi 
.68242: callq .90944 
.68247: testl %eax, %eax 
.68249: jne .68328 
.68251: movzbl (%rbx), %ecx 
.68254: leal -0x30(%rcx), %edx 
.68257: movq (%rsp), %rcx 
.68261: cmpb $9, %dl 
.68264: ja .68288 
.68266: jmp .68311 
.68272: movzbl 1(%rbx), %edi 
.68276: addq $1, %rbx 
.68280: leal -0x30(%rdi), %edx 
.68283: cmpb $9, %dl 
.68286: jbe .68311 
.68288: cmpq %rbx, %rcx 
.68291: jne .68272 
.68293: cmpb $0x42, -1(%rcx) 
.68297: je .68496 
.68303: orb $0x80, %r12b 
.68307: orl $0x20, %r12d 
.68311: movq (%rbp), %rdx 
.68315: movl %r12d, (%r13) 
.68319: jmp .68340 
.68328: movl $0, (%r13) 
.68336: movq (%rbp), %rdx 
.68340: testq %rdx, %rdx 
.68343: jne .68188 
.68349: leaq .114606(%rip), %rdi 
.68356: callq .18192 
.68361: cmpq $1, %rax 
.68365: sbbq %rax, %rax 
.68368: andl $0x200, %eax 
.68373: addq $0x200, %rax 
.68379: movq %rax, (%rbp) 
.68383: movl $4, %eax 
.68388: jmp .68188 
.68496: orl $0x180, %r12d 
.68503: cmpb $0x69, -2(%rcx) 
.68507: jne .68311 
.68513: jmp .68307 
.68539: hlt 
