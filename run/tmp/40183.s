.40183: nopw (%rax, %rax) 
.40192: pushq %r13 
.40194: pushq %r12 
.40196: pushq %rbp 
.40197: movl %edi, %ebp 
.40199: pushq %rbx 
.40200: subq $8, %rsp 
.40204: movq .148400(%rip), %r9 
.40211: movq .147968(%rip), %rcx 
.40218: cmpq %rcx, %r9 
.40221: movq %rcx, %r12 
.40224: cmovbeq %r9, %r12 
.40228: cmpq .144096(%rip), %r12 
.40235: jbe .40499 
.40241: movq %rcx, %rax 
.40244: movq .147976(%rip), %rdi 
.40251: shrq $1, %rax 
.40254: cmpq %rax, %r12 
.40257: jb .40857 
.40263: movl $0x18, %edx 
.40268: movq %rdx, %rax 
.40271: mulq %rcx 
.40274: seto %dl 
.40277: movzbl %dl, %edx 
.40280: testq %rax, %rax 
.40283: js .40913 
.40289: testq %rdx, %rdx 
.40292: jne .40913 
.40298: leaq (%rcx, %rcx, 2), %rsi 
.40302: shlq $3, %rsi 
.40306: callq .88352 
.40311: movq .147968(%rip), %rbx 
.40318: movq %rax, .147976(%rip) 
.40325: movq .144096(%rip), %rcx 
.40332: movq %rbx, %rdi 
.40335: xorl %eax, %eax 
.40337: subq %rcx, %rdi 
.40340: addq $1, %rcx 
.40344: addq %rbx, %rcx 
.40347: movq %rdi, %rsi 
.40350: setb %al 
.40353: imulq %rcx, %rsi 
.40357: testq %rax, %rax 
.40360: jne .40913 
.40366: movq %rsi, %rax 
.40369: xorl %edx, %edx 
.40371: divq %rdi 
.40374: cmpq %rax, %rcx 
.40377: jne .40913 
.40383: movq %rsi, %rdi 
.40386: xorl %eax, %eax 
.40388: shrq $1, %rdi 
.40391: shrq $0x3e, %rsi 
.40395: setne %al 
.40398: shlq $3, %rdi 
.40402: js .40913 
.40408: testq %rax, %rax 
.40411: jne .40913 
.40417: callq .88256 
.40422: movq %rax, %rdx 
.40425: movq .144096(%rip), %rax 
.40432: cmpq %rax, %rbx 
.40435: jbe .40485 
.40437: movq .147976(%rip), %rdi 
.40444: leaq 8(, %rax, 8), %rax 
.40452: leaq 8(, %rbx, 8), %rsi 
.40460: nopl (%rax) 
.40464: leaq (%rax, %rax, 2), %rcx 
.40468: movq %rdx, -8(%rdi, %rcx) 
.40473: addq %rax, %rdx 
.40476: addq $8, %rax 
.40480: cmpq %rsi, %rax 
.40483: jne .40464 
.40485: movq %rbx, .144096(%rip) 
.40492: movq .148400(%rip), %r9 
.40499: testq %r12, %r12 
.40502: je .40585 
.40504: movq .147976(%rip), %rdi 
.40511: leaq 3(%r12, %r12, 2), %r8 
.40516: xorl %esi, %esi 
.40518: movl $3, %ecx 
.40523: nopl (%rax, %rax) 
.40528: movq -8(%rdi, %rcx, 8), %rax 
.40533: movb $1, -0x18(%rdi, %rcx, 8) 
.40538: addq $8, %rsi 
.40542: movq %rcx, -0x10(%rdi, %rcx, 8) 
.40547: leaq (%rax, %rsi), %rdx 
.40551: nopw (%rax, %rax) 
.40560: movq $3, (%rax) 
.40567: addq $8, %rax 
.40571: cmpq %rax, %rdx 
.40574: jne .40560 
.40576: addq $3, %rcx 
.40580: cmpq %rcx, %r8 
.40583: jne .40528 
.40585: xorl %ebx, %ebx 
.40587: testq %r9, %r9 
.40590: je .40797 
.40596: nopl (%rax) 
.40600: movq .148384(%rip), %rax 
.40607: movq (%rax, %rbx, 8), %rdi 
.40611: callq .39760 
.40616: movq .148400(%rip), %r10 
.40623: movq %rax, %r8 
.40626: testq %r12, %r12 
.40629: je .40784 
.40635: movq .148144(%rip), %r11 
.40642: movq .147976(%rip), %rsi 
.40649: xorl %ecx, %ecx 
.40651: leaq 2(%rax), %r9 
.40655: jmp .40750 
.40664: leaq -1(%r10, %rcx), %rax 
.40669: xorl %edx, %edx 
.40671: divq %rcx 
.40674: xorl %edx, %edx 
.40676: movq %rax, %r13 
.40679: movq %rbx, %rax 
.40682: divq %r13 
.40685: movq %rax, %r13 
.40688: movq 0x10(%rsi), %rdx 
.40692: cmpq %rdi, %r13 
.40695: movq %r8, %rax 
.40698: cmovneq %r9, %rax 
.40702: leaq (%rdx, %r13, 8), %rdi 
.40706: movq (%rdi), %rdx 
.40709: cmpq %rax, %rdx 
.40712: jae .40741 
.40714: movq 8(%rsi), %r13 
.40718: subq %rdx, %r13 
.40721: movq %r13, %rdx 
.40724: addq %rax, %rdx 
.40727: movq %rdx, 8(%rsi) 
.40731: movq %rax, (%rdi) 
.40734: cmpq %r11, 8(%rsi) 
.40738: setb (%rsi) 
.40741: addq $0x18, %rsi 
.40745: cmpq %rcx, %r12 
.40748: je .40784 
.40750: movq %rcx, %rdi 
.40753: addq $1, %rcx 
.40757: cmpb $0, (%rsi) 
.40760: je .40741 
.40762: testb %bpl, %bpl 
.40765: jne .40664 
.40767: movq %rbx, %rax 
.40770: xorl %edx, %edx 
.40772: divq %rcx 
.40775: movq %rdx, %r13 
.40778: jmp .40688 
.40784: addq $1, %rbx 
.40788: cmpq %r10, %rbx 
.40791: jb .40600 
.40797: cmpq $1, %r12 
.40801: jbe .40843 
.40803: movq .147976(%rip), %rdx 
.40810: leaq (%r12, %r12, 2), %rax 
.40814: leaq -0x18(%rdx, %rax, 8), %rax 
.40819: jmp .40838 
.40824: subq $1, %r12 
.40828: subq $0x18, %rax 
.40832: cmpq $1, %r12 
.40836: je .40843 
.40838: cmpb $0, (%rax) 
.40841: je .40824 
.40843: addq $8, %rsp 
.40847: movq %r12, %rax 
.40850: popq %rbx 
.40851: popq %rbp 
.40852: popq %r12 
.40854: popq %r13 
.40856: ret 
.40857: movl $0x30, %edx 
.40862: movq %rdx, %rax 
.40865: mulq %r12 
.40868: seto %dl 
.40871: movzbl %dl, %edx 
.40874: testq %rax, %rax 
.40877: js .40913 
.40879: testq %rdx, %rdx 
.40882: jne .40913 
.40884: leaq (%r12, %r12), %rbx 
.40888: leaq (%rbx, %r12), %rsi 
.40892: shlq $4, %rsi 
.40896: callq .88352 
.40901: movq %rax, .147976(%rip) 
.40908: jmp .40325 
.40913: hlt 
