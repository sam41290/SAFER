.35474: subq $8, %rsp 
.35478: movq .148176(%rip), %rsi 
.35485: xorl %ecx, %ecx 
.35487: movq %r15, %r9 
.35490: movl 0xc4(%r12), %edx 
.35498: pushq 0x10(%r12) 
.35503: xorl $1, %r14d 
.35507: movq %r13, %rdi 
.35510: movzbl %r14b, %r8d 
.35514: callq .34384 
.35519: movq %rax, %r12 
.35522: callq .32912 
.35527: popq %rcx 
.35528: popq %rsi 
.35529: addq $0x18, %rsp 
.35533: movq %r12, %rax 
.35536: popq %rbx 
.35537: popq %rbp 
.35538: popq %r12 
.35540: popq %r13 
.35542: popq %r14 
.35544: popq %r15 
.35546: ret 
.35547: nopl (%rax, %rax) 
.35552: cmpb $0, 0xb9(%rdi) 
.35559: movl 0xac(%rdi), %esi 
.35565: jne .35904 
.35571: movl $0xc, %edi 
.35576: callq .27456 
.35581: movl $0xffffffff, %edx 
.35586: testb %al, %al 
.35588: je .35636 
.35590: movl $0xc0, %ecx 
.35595: jmp .35742 
.35636: movzbl 0xb8(%r12), %ecx 
.35645: testb %cl, %cl 
.35647: jne .35923 
.35653: movl 0xa8(%r12), %ecx 
.35661: leaq .99936(%rip), %rax 
.35668: movl (%rax, %rcx, 4), %eax 
.35671: cmpl $7, %eax 
.35674: sete %cl 
.35677: cmpl $5, %eax 
.35680: je .36064 
.35686: testl %edx, %edx 
.35688: jne .36508 
.35694: testb %cl, %cl 
.35696: je .36508 
.35702: cmpb $0, .148368(%rip) 
.35709: movl $0xd0, %ecx 
.35714: jne .35742 
.35716: movl $0xd, %edi 
.35721: callq .27456 
.35726: cmpb $1, %al 
.35728: sbbq %rcx, %rcx 
.35731: andq $0xffffffffffffffa0, %rcx 
.35735: addq $0xd0, %rcx 
.35742: leaq .143456(%rip), %rbx 
.35749: addq %rbx, %rcx 
.35752: cmpq $0, 8(%rcx) 
.35757: jne .35779 
.35759: movl $4, %edi 
.35764: callq .27456 
.35769: testb %al, %al 
.35771: je .35474 
.35777: xorl %ecx, %ecx 
.35779: subq $8, %rsp 
.35783: xorl $1, %r14d 
.35787: movq %r15, %r9 
.35790: movq %r13, %rdi 
.35793: movl 0xc4(%r12), %edx 
.35801: pushq 0x10(%r12) 
.35806: movzbl %r14b, %r8d 
.35810: movq .148176(%rip), %rsi 
.35817: callq .34384 
.35822: movq %rax, %r12 
.35825: callq .32912 
.35830: callq .32656 
.35835: movq .148144(%rip), %rcx 
.35842: popq %rax 
.35843: popq %rdx 
.35844: testq %rcx, %rcx 
.35847: je .35529 
.35853: movq %rbp, %rax 
.35856: xorl %edx, %edx 
.35858: divq %rcx 
.35861: xorl %edx, %edx 
.35863: movq %rax, %rsi 
.35866: leaq -1(%r12, %rbp), %rax 
.35871: divq %rcx 
.35874: cmpq %rax, %rsi 
.35877: je .35529 
.35883: leaq .143832(%rip), %rsi 
.35890: leaq -8(%rsi), %rdi 
.35894: callq .32752 
.35899: jmp .35529 
.35904: movzbl 0xb8(%r12), %ecx 
.35913: xorl %edx, %edx 
.35915: testb %cl, %cl 
.35917: je .35653 
.35923: movl %esi, %eax 
.35925: andl $0xf000, %eax 
.35930: cmpl $0x8000, %eax 
.35935: je .36176 
.35941: cmpl $0x4000, %eax 
.35946: je .36288 
.35952: cmpl $0xa000, %eax 
.35957: je .36384 
.35963: movl $0x80, %ecx 
.35968: cmpl $0x1000, %eax 
.35973: je .35742 
.35979: movl $0x90, %ecx 
.35984: cmpl $0xc000, %eax 
.35989: je .35742 
.35995: movl $0xa0, %ecx 
.36000: cmpl $0x6000, %eax 
.36005: je .35742 
.36011: cmpl $0x2000, %eax 
.36016: movl $0xb0, %ecx 
.36021: movl $0xd0, %ebx 
.36026: cmovneq %rbx, %rcx 
.36030: jmp .35742 
.36064: movq %r13, %rdi 
.36067: callq .18624 
.36072: movq .148232(%rip), %rbx 
.36079: movq %rax, %rcx 
.36082: testq %rbx, %rbx 
.36085: je .36145 
.36087: nopw (%rax, %rax) 
.36096: movq (%rbx), %rdx 
.36099: cmpq %rdx, %rcx 
.36102: jb .36136 
.36104: movq %rcx, %rdi 
.36107: movq 8(%rbx), %rsi 
.36111: movq %rcx, 8(%rsp) 
.36116: subq %rdx, %rdi 
.36119: addq %r13, %rdi 
.36122: callq .55440 
.36127: movq 8(%rsp), %rcx 
.36132: testl %eax, %eax 
.36134: je .36160 
.36136: movq 0x20(%rbx), %rbx 
.36140: testq %rbx, %rbx 
.36143: jne .36096 
.36145: movl $0x50, %ecx 
.36150: jmp .35742 
.36160: leaq 0x10(%rbx), %rcx 
.36164: jmp .35752 
.36176: testl $0x800, %esi 
.36182: je .36208 
.36184: movl $0x10, %edi 
.36189: callq .27456 
.36194: testb %al, %al 
.36196: je .36208 
.36198: movl $0x100, %ecx 
.36203: jmp .35742 
.36208: testl $0x400, %esi 
.36214: jne .36264 
.36216: movl $0x15, %edi 
.36221: callq .27456 
.36226: testb %al, %al 
.36228: je .36400 
.36234: cmpb $0, 0xc0(%r12) 
.36243: je .36400 
.36249: movl $0x150, %ecx 
.36254: jmp .35742 
.36264: movl $0x11, %edi 
.36269: callq .27456 
.36274: testb %al, %al 
.36276: je .36216 
.36278: movl $0x110, %ecx 
.36283: jmp .35742 
.36288: movl %esi, %eax 
.36290: andl $0x202, %eax 
.36295: cmpl $0x202, %eax 
.36300: je .36480 
.36306: testb $2, %sil 
.36310: je .36335 
.36312: movl $0x13, %edi 
.36317: callq .27456 
.36322: movl $0x130, %ecx 
.36327: testb %al, %al 
.36329: jne .35742 
.36335: andl $0x200, %esi 
.36341: movl $0x60, %ecx 
.36346: je .35742 
.36352: movl $0x12, %edi 
.36357: callq .27456 
.36362: cmpb $1, %al 
.36364: sbbq %rcx, %rcx 
.36367: andb $0x40, %cl 
.36370: addq $0x120, %rcx 
.36377: jmp .35742 
.36384: movl $7, %eax 
.36389: jmp .35686 
.36400: andl $0x49, %esi 
.36403: je .36432 
.36405: movl $0xe, %edi 
.36410: callq .27456 
.36415: testb %al, %al 
.36417: je .36432 
.36419: movl $0xe0, %ecx 
.36424: jmp .35742 
.36432: cmpq $1, 0x28(%r12) 
.36438: jbe .36064 
.36444: movl $0x16, %edi 
.36449: callq .27456 
.36454: testb %al, %al 
.36456: je .36064 
.36462: movl $0x160, %ecx 
.36467: jmp .35742 
.36480: movl $0x14, %edi 
.36485: callq .27456 
.36490: movl $0x140, %ecx 
.36495: testb %al, %al 
.36497: jne .35742 
.36503: jmp .36306 
.36508: shlq $4, %rax 
.36512: movq %rax, %rcx 
.36515: jmp .35742 
