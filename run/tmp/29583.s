.29583: nop 
.29584: pushq %r14 
.29586: pushq %r13 
.29588: movzbl %sil, %r13d 
.29592: pushq %r12 
.29594: movq %rdi, %r12 
.29597: pushq %rbp 
.29598: pushq %rbx 
.29599: testq %rdi, %rdi 
.29602: je .29626 
.29604: cmpq $0, .148424(%rip) 
.29612: je .29626 
.29614: movq %rdi, %rsi 
.29617: xorl %edx, %edx 
.29619: xorl %edi, %edi 
.29621: callq .28288 
.29626: movq .148400(%rip), %rax 
.29633: leaq -1(%rax), %rbx 
.29637: testq %rax, %rax 
.29640: jne .29662 
.29642: jmp .29952 
.29648: subq $1, %rbx 
.29652: cmpq $-1, %rbx 
.29656: je .29808 
.29662: movq .148384(%rip), %rax 
.29669: movq (%rax, %rbx, 8), %rbp 
.29673: movl 0xa8(%rbp), %eax 
.29679: cmpl $3, %eax 
.29682: je .29689 
.29684: cmpl $9, %eax 
.29687: jne .29648 
.29689: movq (%rbp), %r14 
.29693: testq %r12, %r12 
.29696: je .29888 
.29702: movq %r14, %rdi 
.29705: callq .57664 
.29710: cmpb $0x2e, (%rax) 
.29713: je .29912 
.29719: cmpb $0x2f, (%r14) 
.29723: je .29888 
.29729: movq %r14, %rsi 
.29732: xorl %edx, %edx 
.29734: movq %r12, %rdi 
.29737: callq .58640 
.29742: movq 8(%rbp), %rsi 
.29746: movl %r13d, %edx 
.29749: movq %rax, %r14 
.29752: movq %rax, %rdi 
.29755: callq .28288 
.29760: movq %r14, %rdi 
.29763: callq .18128 
.29768: cmpl $9, 0xa8(%rbp) 
.29775: jne .29648 
.29781: movq %rbp, %rdi 
.29784: subq $1, %rbx 
.29788: callq .28448 
.29793: cmpq $-1, %rbx 
.29797: jne .29662 
.29803: nopl (%rax, %rax) 
.29808: movq .148400(%rip), %rdx 
.29815: testq %rdx, %rdx 
.29818: je .29952 
.29824: movq .148384(%rip), %rsi 
.29831: leaq (%rsi, %rdx, 8), %rdi 
.29835: movq %rsi, %rax 
.29838: xorl %edx, %edx 
.29840: movq (%rax), %rcx 
.29843: cmpl $9, 0xa8(%rcx) 
.29850: movq %rcx, (%rsi, %rdx, 8) 
.29854: setne %cl 
.29857: addq $8, %rax 
.29861: movzbl %cl, %ecx 
.29864: addq %rcx, %rdx 
.29867: cmpq %rax, %rdi 
.29870: jne .29840 
.29872: popq %rbx 
.29873: popq %rbp 
.29874: movq %rdx, .148400(%rip) 
.29881: popq %r12 
.29883: popq %r13 
.29885: popq %r14 
.29887: ret 
.29888: movq 8(%rbp), %rsi 
.29892: movl %r13d, %edx 
.29895: movq %r14, %rdi 
.29898: callq .28288 
.29903: jmp .29768 
.29912: xorl %edx, %edx 
.29914: cmpb $0x2e, 1(%rax) 
.29918: sete %dl 
.29921: movzbl 1(%rax, %rdx), %eax 
.29926: testb %al, %al 
.29928: je .29648 
.29934: cmpb $0x2f, %al 
.29936: je .29648 
.29942: jmp .29719 
.29952: xorl %edx, %edx 
.29954: popq %rbx 
.29955: popq %rbp 
.29956: movq %rdx, .148400(%rip) 
.29963: popq %r12 
.29965: popq %r13 
.29967: popq %r14 
.29969: ret 
