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
.39568: hlt 
