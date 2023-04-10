.19168: endbr64 
.19172: bnd jmpq *.142944(%rip) 
.71424: pushq %r15 
.71426: pushq %r14 
.71428: pushq %r13 
.71430: pushq %r12 
.71432: pushq %rbp 
.71433: movq %rcx, %rbp 
.71436: pushq %rbx 
.71437: movq %rdi, %rbx 
.71440: subq $0x38, %rsp 
.71444: movq %rsi, 0x10(%rsp) 
.71449: movq %rdx, 0x18(%rsp) 
.71454: cmpq $2, %rsi 
.71458: ja .71528 
.71460: je .71480 
.71462: addq $0x38, %rsp 
.71466: popq %rbx 
.71467: popq %rbp 
.71468: popq %r12 
.71470: popq %r13 
.71472: popq %r14 
.71474: popq %r15 
.71476: ret 
.71480: movq 8(%rdi), %r13 
.71484: movq (%rdi), %r12 
.71487: movq %r13, %rsi 
.71490: movq %r12, %rdi 
.71493: callq *%rcx 
.71495: testl %eax, %eax 
.71497: jle .71462 
.71499: movq %r13, (%rbx) 
.71502: movq %r12, 8(%rbx) 
.71506: addq $0x38, %rsp 
.71510: popq %rbx 
.71511: popq %rbp 
.71512: popq %r12 
.71514: popq %r13 
.71516: popq %r14 
.71518: popq %r15 
.71520: ret 
.71528: movq 0x10(%rsp), %r15 
.71533: movq 0x18(%rsp), %r14 
.71538: movq %r15, %rcx 
.71541: movq %r15, %rsi 
.71544: movq %r14, %rdx 
.71547: shrq $1, %rcx 
.71550: leaq (%rdi, %rcx, 8), %rdi 
.71554: subq %rcx, %rsi 
.71557: movq %rcx, 8(%rsp) 
.71562: movq %rbp, %rcx 
.71565: movq %rdi, 0x28(%rsp) 
.71570: callq .71424 
.71575: cmpq $3, %r15 
.71579: jne .71712 
.71585: movq (%rbx), %r15 
.71588: movq %r15, (%r14) 
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
.71712: movq 0x10(%rsp), %r15 
.71717: movq 0x18(%rsp), %r14 
.71722: movq %rbp, %rcx 
.71725: movq 8(%rsp), %rsi 
.71730: shrq $2, %r15 
.71734: movq %r14, %rdx 
.71737: leaq (%rbx, %r15, 8), %r12 
.71741: subq %r15, %rsi 
.71744: movq %r15, 0x20(%rsp) 
.71749: movq %r15, %r13 
.71752: movq %r12, %rdi 
.71755: callq .71424 
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
.71999: nop 
.72000: endbr64 
.72004: movq %rdx, %rcx 
.72007: leaq (%rdi, %rsi, 8), %rdx 
.72011: jmp .71424 
