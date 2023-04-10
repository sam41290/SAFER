.19552: endbr64 
.19556: bnd jmpq *.143136(%rip) 
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
.54877: nopl (%rax) 
.54880: leaq .114245(%rip), %rsi 
.54887: xorl %edi, %edi 
.54889: callq .18592 
.54894: movq %rax, %r12 
.54897: jmp .54816 
