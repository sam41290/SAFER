.53807: nop 
.53808: movq 0x10(%rbx), %rsi 
.53812: addq $0x10, %rbx 
.53816: testq %rsi, %rsi 
.53819: je .53833 
.53821: movq %r12, %rdi 
.53824: callq .19072 
.53829: testl %eax, %eax 
.53831: jne .53808 
.53833: movq 8(%rbx), %r13 
.53837: movl $5, %edx 
.53842: leaq .104724(%rip), %rsi 
.53849: xorl %edi, %edi 
.53851: testq %r13, %r13 
.53854: je .54049 
.53860: callq .18592 
.53865: leaq .113496(%rip), %rcx 
.53872: movl $1, %edi 
.53877: leaq .104747(%rip), %rdx 
.53884: movq %rax, %rsi 
.53887: xorl %eax, %eax 
.53889: callq .19472 
.53894: movl $5, %edi 
.53899: xorl %esi, %esi 
.53901: callq .19456 
.53906: movq %rax, %rdi 
.53909: testq %rax, %rax 
.53912: je .53939 
.53914: movl $3, %edx 
.53919: leaq .104761(%rip), %rsi 
.53926: callq .18288 
.53931: testl %eax, %eax 
.53933: jne .54186 
.53939: xorl %edi, %edi 
.53941: movl $5, %edx 
.53946: leaq .113608(%rip), %rsi 
.53953: callq .18592 
.53958: movq %r12, %rcx 
.53961: movl $1, %edi 
.53966: leaq .113496(%rip), %rdx 
.53973: movq %rax, %rsi 
.53976: xorl %eax, %eax 
.53978: hlt 
.54049: callq .18592 
.54054: leaq .113496(%rip), %rcx 
.54061: movl $1, %edi 
.54066: leaq .104747(%rip), %rdx 
.54073: movq %rax, %rsi 
.54076: xorl %eax, %eax 
.54078: hlt 
.54186: xorl %edi, %edi 
.54188: movl $5, %edx 
.54193: leaq .113536(%rip), %rsi 
.54200: callq .18592 
.54205: movq %r12, %rdx 
.54208: movl $1, %edi 
.54213: movq %rax, %rsi 
.54216: xorl %eax, %eax 
.54218: callq .19472 
.54223: jmp .53939 
