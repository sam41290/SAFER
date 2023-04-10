.19552: endbr64 
.19556: bnd jmpq *.143136(%rip) 
.54768: endbr64 
.54772: pushq %r13 
.54774: movq %rsi, %r13 
.54777: pushq %r12 
.54779: pushq %rbp 
.54780: movq %rdi, %rbp 
.54783: pushq %rbx 
.54784: subq $8, %rsp 
.54788: cmpq $-1, %rdx 
.54792: movl $5, %edx 
.54797: je .54880 
.54799: leaq .114272(%rip), %rsi 
.54806: xorl %edi, %edi 
.54808: callq .18592 
.54813: movq %rax, %r12 
.54816: movq %rbp, %rsi 
.54819: movl $1, %edi 
.54824: callq .86048 
.54829: movq %r13, %rdx 
.54832: movl $8, %esi 
.54837: xorl %edi, %edi 
.54839: movq %rax, %rbx 
.54842: callq .85008 
.54847: addq $8, %rsp 
.54851: movq %rbx, %r8 
.54854: movq %r12, %rdx 
.54857: popq %rbx 
.54858: movq %rax, %rcx 
.54861: popq %rbp 
.54862: xorl %esi, %esi 
.54864: popq %r12 
.54866: xorl %edi, %edi 
.54868: xorl %eax, %eax 
.54870: popq %r13 
.54872: jmp .19552 
.54880: leaq .114245(%rip), %rsi 
.54887: xorl %edi, %edi 
.54889: callq .18592 
.54894: movq %rax, %r12 
.54897: jmp .54816 
