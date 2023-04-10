.90935: nopw (%rax, %rax) 
.90944: endbr64 
.90948: pushq %r15 
.90950: pushq %r14 
.90952: pushq %r13 
.90954: pushq %r12 
.90956: pushq %rbp 
.90957: pushq %rbx 
.90958: subq $0x28, %rsp 
.90962: movq %fs:0x28, %rax 
.90971: movq %rax, 0x18(%rsp) 
.90976: xorl %eax, %eax 
.90978: cmpl $0x24, %edx 
.90981: ja .92024 
.90987: movq %rsi, %rbp 
.90990: testq %rsi, %rsi 
.90993: leaq 0x10(%rsp), %rax 
.90998: movq %rdi, %r12 
.91001: movl %edx, 8(%rsp) 
.91005: cmoveq %rax, %rbp 
.91009: movq %rcx, %rbx 
.91012: movq %r8, %r15 
.91015: callq .18272 
.91020: movl $0, (%rax) 
.91026: movq %rax, %r13 
.91029: movzbl (%r12), %r14d 
.91034: callq .19840 
.91039: movl 8(%rsp), %edx 
.91043: movq (%rax), %rsi 
.91046: movq %r12, %rax 
.91049: jmp .91065 
.91056: movzbl 1(%rax), %r14d 
.91061: addq $1, %rax 
.91065: movzbl %r14b, %ecx 
.91069: testb $0x20, 1(%rsi, %rcx, 2) 
.91074: jne .91056 
.91076: cmpb $0x2d, %r14b 
.91080: je .91195 
.91082: xorl %ecx, %ecx 
.91084: movq %rbp, %rsi 
.91087: movq %r12, %rdi 
.91090: callq .18880 
.91095: movq (%rbp), %r14 
.91099: movq %rax, %rdx 
.91102: cmpq %r12, %r14 
.91105: je .91208 
.91107: movl (%r13), %eax 
.91111: testl %eax, %eax 
.91113: jne .91184 
.91115: xorl %r12d, %r12d 
.91118: testq %r15, %r15 
.91121: je .91136 
.91123: movzbl (%r14), %r13d 
.91127: testb %r13b, %r13b 
.91130: jne .91408 
.91136: movq %rdx, (%rbx) 
.91139: movq 0x18(%rsp), %rax 
.91144: xorq %fs:0x28, %rax 
.91153: jne .92055 
.91159: addq $0x28, %rsp 
.91163: movl %r12d, %eax 
.91166: popq %rbx 
.91167: popq %rbp 
.91168: popq %r12 
.91170: popq %r13 
.91172: popq %r14 
.91174: popq %r15 
.91176: ret 
.91184: movl $1, %r12d 
.91190: cmpl $0x22, %eax 
.91193: je .91118 
.91195: movl $4, %r12d 
.91201: jmp .91139 
.91208: testq %r15, %r15 
.91211: je .91195 
.91213: movzbl (%r12), %r13d 
.91218: testb %r13b, %r13b 
.91221: je .91195 
.91223: movsbl %r13b, %esi 
.91227: movq %r15, %rdi 
.91230: xorl %r12d, %r12d 
.91233: callq .18704 
.91238: movl $1, %edx 
.91243: testq %rax, %rax 
.91246: je .91195 
.91248: leal -0x45(%r13), %eax 
.91252: cmpb $0x2f, %al 
.91254: ja .91276 
.91256: leaq .118752(%rip), %rcx 
.91263: movzbl %al, %eax 
.91266: movslq (%rcx, %rax, 4), %rax 
.91270: addq %rcx, %rax 
.91273: jmpq *%rax 
.91276: movl $1, %ecx 
.91281: movl $0x400, %esi 
.91286: leal -0x42(%r13), %eax 
.91290: cmpb $0x35, %al 
.91292: ja .91439 
.91298: leaq .118944(%rip), %rdi 
.91305: movzbl %al, %eax 
.91308: movslq (%rdi, %rax, 4), %rax 
.91312: addq %rdi, %rax 
.91315: jmpq *%rax 
.91358: addb %bh, (%rcx, %rbp, 2) 
.91361: je .91863 
.91367: cmpb $0x42, %al 
.91369: je .92009 
.91375: leal -0x45(%r13), %eax 
.91379: cmpb $0x2f, %al 
.91381: ja .91439 
.91383: leaq .119160(%rip), %rcx 
.91390: movzbl %al, %eax 
.91393: movslq (%rcx, %rax, 4), %rax 
.91397: addq %rcx, %rax 
.91400: jmpq *%rax 
.91408: movsbl %r13b, %esi 
.91412: movq %r15, %rdi 
.91415: movq %rdx, 8(%rsp) 
.91420: callq .18704 
.91425: movq 8(%rsp), %rdx 
.91430: testq %rax, %rax 
.91433: jne .91248 
.91439: movq %rdx, (%rbx) 
.91442: orl $2, %r12d 
.91446: jmp .91139 
.91707: movl $1, %ecx 
.91712: addq %r14, %rcx 
.91715: movl %r12d, %eax 
.91718: orl $2, %eax 
.91721: movq %rcx, (%rbp) 
.91725: cmpb $0, (%rcx) 
.91728: cmovnel %eax, %r12d 
.91732: jmp .91136 
.91863: xorl %ecx, %ecx 
.91865: cmpb $0x42, 2(%r14) 
.91870: movl $0x400, %esi 
.91875: sete %cl 
.91878: leal 1(%rcx, %rcx), %ecx 
.91882: jmp .91286 
.92009: movl $2, %ecx 
.92014: movl $0x3e8, %esi 
.92019: jmp .91286 
.92024: leaq .119352(%rip), %rcx 
.92031: movl $0x60, %edx 
.92036: leaq .117984(%rip), %rsi 
.92043: leaq .118000(%rip), %rdi 
.92050: hlt 
.92055: hlt 
