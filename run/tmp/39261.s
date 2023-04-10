.37661: movq %r13, %r9 
.37664: leaq .104463(%rip), %rcx 
.37671: movq %rbx, %rdi 
.37674: xorl %eax, %eax 
.37676: movq $-1, %rdx 
.37683: movl $1, %esi 
.37688: callq .19856 
.37693: movq %rbx, %rdi 
.37696: callq .18624 
.37701: leaq (%rbx, %rax), %r13 
.37705: movq .144008(%rip), %rsi 
.37712: movq %rbp, %rdi 
.37715: subq %rbp, %r13 
.37718: callq .19024 
.37723: movq %r13, %rcx 
.37726: xorl %esi, %esi 
.37728: movq %r12, %rdi 
.37731: leaq .147872(%rip), %rdx 
.37738: addq %r13, .147960(%rip) 
.37745: callq .35424 
.37750: movl 0xa8(%r12), %edx 
.37758: movq %rax, %rbp 
.37761: cmpl $6, %edx 
.37764: je .38200 
.37770: movl .148244(%rip), %eax 
.37776: testl %eax, %eax 
.37778: jne .38768 
.37784: movq 0x1318(%rsp), %rax 
.37792: xorq %fs:0x28, %rax 
.37801: jne .39568 
.37807: addq $0x1328, %rsp 
.37814: popq %rbx 
.37815: popq %rbp 
.37816: popq %r12 
.37818: popq %r13 
.37820: popq %r14 
.37822: popq %r15 
.37824: ret 
.38200: cmpq $0, 8(%r12) 
.38206: je .37784 
.38212: movq .144008(%rip), %rcx 
.38219: movl $4, %edx 
.38224: movl $1, %esi 
.38229: leaq .104468(%rip), %rdi 
.38236: callq .19408 
.38241: xorl %edx, %edx 
.38243: leaq 4(%r13, %rbp), %rcx 
.38248: movq %r12, %rdi 
.38251: movl $1, %esi 
.38256: addq $4, .147960(%rip) 
.38264: callq .35424 
.38269: movl .148244(%rip), %edx 
.38275: testl %edx, %edx 
.38277: je .37784 
.38283: movl 0xac(%r12), %esi 
.38291: xorl %edx, %edx 
.38293: movl $1, %edi 
.38298: callq .31536 
.38303: jmp .37784 
.38768: movzbl 0xb8(%r12), %edi 
.38777: movl 0x30(%r12), %esi 
.38782: callq .31536 
.38787: jmp .37784 
.39261: movl .143380(%rip), %r8d 
.39268: movq %rax, %r13 
.39271: testl %r8d, %r8d 
.39274: jns .37661 
.39280: leaq 0x70(%rsp), %r14 
.39285: movq .148136(%rip), %rdi 
.39292: leaq 0x18(%rsp), %rsi 
.39297: movq $0, 0x18(%rsp) 
.39306: movq %r14, %rdx 
.39309: callq .94256 
.39314: testq %rax, %rax 
.39317: je .39382 
.39319: cmpb $0, .144328(%rip) 
.39326: movq .148136(%rip), %r8 
.39333: movq .143424(%rip), %rdx 
.39340: jne .39504 
.39346: leaq 0xe0(%rsp), %r15 
.39354: xorl %r9d, %r9d 
.39357: movq %r14, %rcx 
.39360: movl $0x3e9, %esi 
.39365: movq %r15, %rdi 
.39368: callq .78464 
.39373: testq %rax, %rax 
.39376: jne .39531 
.39382: movl .143380(%rip), %r8d 
.39389: testl %r8d, %r8d 
.39392: jns .37661 
.39398: movl $0, .143380(%rip) 
.39408: xorl %r8d, %r8d 
.39411: jmp .37661 
.39504: movslq 0x80(%rsp), %rdx 
.39512: leaq .144352(%rip), %rax 
.39519: shlq $7, %rdx 
.39523: addq %rax, %rdx 
.39526: jmp .39346 
.39531: xorl %edx, %edx 
.39533: movq %rax, %rsi 
.39536: movq %r15, %rdi 
.39539: callq .70832 
.39544: movl %eax, .143380(%rip) 
.39550: movl %eax, %r8d 
.39553: jmp .39389 
.39568: hlt 
