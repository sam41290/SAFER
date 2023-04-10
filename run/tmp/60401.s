.60401: nopw %cs:(%rax, %rax) 
.60412: nopl (%rax) 
.60416: pushq %r14 
.60418: movq %rdx, %r14 
.60421: pushq %r13 
.60423: movl %ecx, %r13d 
.60426: pushq %r12 
.60428: movq %rdi, %r12 
.60431: pushq %rbp 
.60432: movq %rsi, %rbp 
.60435: pushq %rbx 
.60436: callq .60368 
.60441: movq %rax, (%r14) 
.60444: movq (%rax), %rsi 
.60447: testq %rsi, %rsi 
.60450: je .60577 
.60452: movq %rax, %rbx 
.60455: cmpq %rbp, %rsi 
.60458: je .60664 
.60464: movq %rbp, %rdi 
.60467: callq *0x38(%r12) 
.60472: testb %al, %al 
.60474: je .60568 
.60476: movq (%rbx), %rax 
.60479: testb %r13b, %r13b 
.60482: je .60579 
.60484: movq 8(%rbx), %rdx 
.60488: testq %rdx, %rdx 
.60491: je .60648 
.60497: movdqu (%rdx), %xmm0 
.60501: movups %xmm0, (%rbx) 
.60504: movq $0, (%rdx) 
.60511: movq 0x48(%r12), %rcx 
.60516: movq %rcx, 8(%rdx) 
.60520: popq %rbx 
.60521: movq %rdx, 0x48(%r12) 
.60526: popq %rbp 
.60527: popq %r12 
.60529: popq %r13 
.60531: popq %r14 
.60533: ret 
.60544: movq (%rax), %rsi 
.60547: cmpq %rbp, %rsi 
.60550: je .60592 
.60552: movq %rbp, %rdi 
.60555: callq *0x38(%r12) 
.60560: testb %al, %al 
.60562: jne .60592 
.60564: movq 8(%rbx), %rbx 
.60568: movq 8(%rbx), %rax 
.60572: testq %rax, %rax 
.60575: jne .60544 
.60577: xorl %eax, %eax 
.60579: popq %rbx 
.60580: popq %rbp 
.60581: popq %r12 
.60583: popq %r13 
.60585: popq %r14 
.60587: ret 
.60592: movq 8(%rbx), %rdx 
.60596: movq (%rdx), %rax 
.60599: testb %r13b, %r13b 
.60602: je .60579 
.60604: movq 8(%rdx), %rcx 
.60608: movq %rcx, 8(%rbx) 
.60612: movq $0, (%rdx) 
.60619: movq 0x48(%r12), %rcx 
.60624: movq %rcx, 8(%rdx) 
.60628: popq %rbx 
.60629: movq %rdx, 0x48(%r12) 
.60634: popq %rbp 
.60635: popq %r12 
.60637: popq %r13 
.60639: popq %r14 
.60641: ret 
.60648: movq $0, (%rbx) 
.60655: jmp .60579 
.60664: movq %rsi, %rax 
.60667: jmp .60479 
