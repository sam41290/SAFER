.68057: nopl (%rax) 
.68064: endbr64 
.68068: pushq %r13 
.68070: movq %rsi, %r13 
.68073: pushq %r12 
.68075: pushq %rbp 
.68076: movq %rdx, %rbp 
.68079: pushq %rbx 
.68080: movq %rdi, %rbx 
.68083: subq $0x18, %rsp 
.68087: movq %fs:0x28, %rax 
.68096: movq %rax, 8(%rsp) 
.68101: xorl %eax, %eax 
.68103: testq %rdi, %rdi 
.68106: je .68400 
.68112: xorl %r12d, %r12d 
.68115: cmpb $0x27, (%rbx) 
.68118: jne .68130 
.68120: addq $1, %rbx 
.68124: movl $4, %r12d 
.68130: movl $4, %ecx 
.68135: leaq .114640(%rip), %rdx 
.68142: leaq .141776(%rip), %rsi 
.68149: movq %rbx, %rdi 
.68152: callq .54496 
.68157: testl %eax, %eax 
.68159: js .68224 
.68161: cltq 
.68163: leaq .114640(%rip), %rdx 
.68170: movq $1, (%rbp) 
.68178: orl (%rdx, %rax, 4), %r12d 
.68182: xorl %eax, %eax 
.68184: movl %r12d, (%r13) 
.68188: movq 8(%rsp), %rcx 
.68193: xorq %fs:0x28, %rcx 
.68202: jne .68539 
.68208: addq $0x18, %rsp 
.68212: popq %rbx 
.68213: popq %rbp 
.68214: popq %r12 
.68216: popq %r13 
.68218: ret 
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
.68400: leaq .104988(%rip), %rdi 
.68407: callq .18192 
.68412: movq %rax, %rbx 
.68415: testq %rax, %rax 
.68418: jne .68112 
.68424: leaq .114596(%rip), %rdi 
.68431: callq .18192 
.68436: movq %rax, %rbx 
.68439: testq %rax, %rax 
.68442: jne .68112 
.68448: leaq .114606(%rip), %rdi 
.68455: callq .18192 
.68460: testq %rax, %rax 
.68463: je .68518 
.68465: movq $0x200, (%rbp) 
.68473: xorl %eax, %eax 
.68475: movl $0, (%r13) 
.68483: jmp .68188 
.68496: orl $0x180, %r12d 
.68503: cmpb $0x69, -2(%rcx) 
.68507: jne .68311 
.68513: jmp .68307 
.68518: movq $0x400, (%rbp) 
.68526: movl $0, (%r13) 
.68534: jmp .68188 
.68539: hlt 
