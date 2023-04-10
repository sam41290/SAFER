.18528: endbr64 
.18532: bnd jmpq *.142624(%rip) 
.95100: nopl (%rax) 
.95104: endbr64 
.95108: pushq %r12 
.95110: pushq %rbp 
.95111: movq %rdi, %rbp 
.95114: pushq %rbx 
.95115: callq .19232 
.95120: movq %rbp, %rdi 
.95123: testl %eax, %eax 
.95125: js .95215 
.95127: callq .19392 
.95132: testl %eax, %eax 
.95134: jne .95184 
.95136: movq %rbp, %rdi 
.95139: callq .95248 
.95144: testl %eax, %eax 
.95146: je .95212 
.95148: callq .18272 
.95153: movq %rbp, %rdi 
.95156: movl (%rax), %r12d 
.95159: movq %rax, %rbx 
.95162: callq .18528 
.95167: testl %r12d, %r12d 
.95170: jne .95232 
.95172: popq %rbx 
.95173: popq %rbp 
.95174: popq %r12 
.95176: ret 
.95184: movq %rbp, %rdi 
.95187: callq .19232 
.95192: xorl %esi, %esi 
.95194: movl $1, %edx 
.95199: movl %eax, %edi 
.95201: callq .18832 
.95206: cmpq $-1, %rax 
.95210: jne .95136 
.95212: movq %rbp, %rdi 
.95215: popq %rbx 
.95216: popq %rbp 
.95217: popq %r12 
.95219: jmp .18528 
.95232: movl %r12d, (%rbx) 
.95235: movl $0xffffffff, %eax 
.95240: jmp .95172 
