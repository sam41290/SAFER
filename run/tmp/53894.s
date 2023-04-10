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
