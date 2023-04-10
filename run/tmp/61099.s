.61099: nopl (%rax, %rax) 
.61104: pushq %r15 
.61106: pushq %r14 
.61108: movq %rdi, %r14 
.61111: pushq %r13 
.61113: movl %edx, %r13d 
.61116: pushq %r12 
.61118: movq %rsi, %r12 
.61121: pushq %rbp 
.61122: pushq %rbx 
.61123: subq $8, %rsp 
.61127: movq (%rsi), %rbp 
.61130: cmpq 8(%rsi), %rbp 
.61134: jb .61159 
.61136: jmp .61362 
.61144: addq $0x10, %rbp 
.61148: cmpq %rbp, 8(%r12) 
.61153: jbe .61362 
.61159: movq (%rbp), %r15 
.61163: testq %r15, %r15 
.61166: je .61144 
.61168: movq 8(%rbp), %rbx 
.61172: testq %rbx, %rbx 
.61175: jne .61201 
.61177: jmp .61264 
.61184: movq 8(%rax), %rcx 
.61188: movq %rcx, 8(%rdx) 
.61192: movq %rdx, 8(%rax) 
.61196: testq %rbx, %rbx 
.61199: je .61260 
.61201: movq (%rbx), %r15 
.61204: movq %r14, %rdi 
.61207: movq %r15, %rsi 
.61210: callq .60368 
.61215: movq %rbx, %rdx 
.61218: movq 8(%rbx), %rbx 
.61222: cmpq $0, (%rax) 
.61226: jne .61184 
.61228: movq %r15, (%rax) 
.61231: addq $1, 0x18(%r14) 
.61236: movq $0, (%rdx) 
.61243: movq 0x48(%r14), %rax 
.61247: movq %rax, 8(%rdx) 
.61251: movq %rdx, 0x48(%r14) 
.61255: testq %rbx, %rbx 
.61258: jne .61201 
.61260: movq (%rbp), %r15 
.61264: movq $0, 8(%rbp) 
.61272: testb %r13b, %r13b 
.61275: jne .61144 
.61281: movq %r15, %rsi 
.61284: movq %r14, %rdi 
.61287: callq .60368 
.61292: cmpq $0, (%rax) 
.61296: movq %rax, %rbx 
.61299: je .61392 
.61301: movq 0x48(%r14), %rax 
.61305: testq %rax, %rax 
.61308: je .61402 
.61310: movq 8(%rax), %rdx 
.61314: movq %rdx, 0x48(%r14) 
.61318: movq 8(%rbx), %rdx 
.61322: movq %r15, (%rax) 
.61325: movq %rdx, 8(%rax) 
.61329: movq %rax, 8(%rbx) 
.61333: movq $0, (%rbp) 
.61341: addq $0x10, %rbp 
.61345: subq $1, 0x18(%r12) 
.61351: cmpq %rbp, 8(%r12) 
.61356: ja .61159 
.61362: addq $8, %rsp 
.61366: movl $1, %eax 
.61371: popq %rbx 
.61372: popq %rbp 
.61373: popq %r12 
.61375: popq %r13 
.61377: popq %r14 
.61379: popq %r15 
.61381: ret 
.61392: movq %r15, (%rax) 
.61395: addq $1, 0x18(%r14) 
.61400: jmp .61333 
.61402: movl $0x10, %edi 
.61407: callq .18144 
.61412: testq %rax, %rax 
.61415: jne .61318 
.61417: addq $8, %rsp 
.61421: xorl %eax, %eax 
.61423: popq %rbx 
.61424: popq %rbp 
.61425: popq %r12 
.61427: popq %r13 
.61429: popq %r14 
.61431: popq %r15 
.61433: ret 
