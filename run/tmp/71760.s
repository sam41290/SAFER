.19168: endbr64 
.19172: bnd jmpq *.142944(%rip) 
.71462: addq $0x38, %rsp 
.71466: popq %rbx 
.71467: popq %rbp 
.71468: popq %r12 
.71470: popq %r13 
.71472: popq %r14 
.71474: popq %r15 
.71476: ret 
.71591: movq 0x28(%rsp), %rax 
.71596: movq $0, (%rsp) 
.71604: xorl %r14d, %r14d 
.71607: movq 8(%rsp), %r13 
.71612: movq (%rax), %r12 
.71615: nop 
.71616: movq %r12, %rsi 
.71619: movq %r15, %rdi 
.71622: addq $1, %r14 
.71626: callq *%rbp 
.71628: testl %eax, %eax 
.71630: jle .71672 
.71632: movq %r12, -8(%rbx, %r14, 8) 
.71637: addq $1, %r13 
.71641: cmpq %r13, 0x10(%rsp) 
.71646: je .71888 
.71652: movq (%rbx, %r13, 8), %r12 
.71656: movq %r15, %rdi 
.71659: addq $1, %r14 
.71663: movq %r12, %rsi 
.71666: callq *%rbp 
.71668: testl %eax, %eax 
.71670: jg .71632 
.71672: addq $1, (%rsp) 
.71677: movq (%rsp), %rax 
.71681: movq %r15, -8(%rbx, %r14, 8) 
.71686: cmpq %rax, 8(%rsp) 
.71691: je .71462 
.71697: movq 0x18(%rsp), %rdx 
.71702: movq (%rdx, %rax, 8), %r15 
.71706: jmp .71616 
.71760: movq %r14, %rdx 
.71763: movq %r15, %rsi 
.71766: movq %rbp, %rcx 
.71769: movq %rbx, %rdi 
.71772: movq %r14, 0x18(%rsp) 
.71777: callq .71424 
.71782: movq $0, (%rsp) 
.71790: movq (%r12), %r14 
.71794: movq %r13, %r12 
.71797: movq (%rbx), %r15 
.71800: movq 0x18(%rsp), %r13 
.71805: nopl (%rax) 
.71808: movq %r14, %rsi 
.71811: movq %r15, %rdi 
.71814: addq $8, %r13 
.71818: callq *%rbp 
.71820: testl %eax, %eax 
.71822: jle .71859 
.71824: movq %r14, -8(%r13) 
.71828: addq $1, %r12 
.71832: cmpq %r12, 8(%rsp) 
.71837: je .71958 
.71839: movq (%rbx, %r12, 8), %r14 
.71843: movq %r15, %rdi 
.71846: addq $8, %r13 
.71850: movq %r14, %rsi 
.71853: callq *%rbp 
.71855: testl %eax, %eax 
.71857: jg .71824 
.71859: addq $1, (%rsp) 
.71864: movq (%rsp), %rax 
.71868: movq %r15, -8(%r13) 
.71872: cmpq %rax, 0x20(%rsp) 
.71877: je .71944 
.71879: movq (%rbx, %rax, 8), %r15 
.71883: jmp .71808 
.71888: movq (%rsp), %rax 
.71892: movq 8(%rsp), %r13 
.71897: leaq (%rbx, %r14, 8), %rdi 
.71901: movq 0x18(%rsp), %rcx 
.71906: addq $0x38, %rsp 
.71910: subq %rax, %r13 
.71913: popq %rbx 
.71914: popq %rbp 
.71915: leaq (, %r13, 8), %rdx 
.71923: popq %r12 
.71925: leaq (%rcx, %rax, 8), %rsi 
.71929: popq %r13 
.71931: popq %r14 
.71933: popq %r15 
.71935: jmp .19168 
.71944: movq 8(%rsp), %rax 
.71949: movq %r12, (%rsp) 
.71953: movq %rax, 0x20(%rsp) 
.71958: movq (%rsp), %rax 
.71962: movq 0x20(%rsp), %rdx 
.71967: movq %r13, %rdi 
.71970: subq %rax, %rdx 
.71973: leaq (%rbx, %rax, 8), %rsi 
.71977: shlq $3, %rdx 
.71981: callq .19168 
.71986: movq 0x18(%rsp), %rax 
.71991: movq (%rax), %r15 
.71994: jmp .71591 
