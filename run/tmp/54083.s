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
.54083: movl $5, %edi 
.54088: xorl %esi, %esi 
.54090: callq .19456 
.54095: movq %rax, %rdi 
.54098: testq %rax, %rax 
.54101: je .54124 
.54103: movl $3, %edx 
.54108: leaq .104761(%rip), %rsi 
.54115: callq .18288 
.54120: testl %eax, %eax 
.54122: jne .54183 
.54124: movl $5, %edx 
.54129: leaq .113608(%rip), %rsi 
.54136: xorl %edi, %edi 
.54138: movq %r12, %r13 
.54141: callq .18592 
.54146: movq %r12, %rcx 
.54149: movl $1, %edi 
.54154: leaq .113496(%rip), %rdx 
.54161: movq %rax, %rsi 
.54164: xorl %eax, %eax 
.54166: leaq .104657(%rip), %r12 
.54173: hlt 
.54183: movq %r12, %r13 
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
