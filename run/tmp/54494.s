.54494: nop 
.54496: endbr64 
.54500: pushq %r15 
.54502: pushq %r14 
.54504: movq %rdi, %r14 
.54507: pushq %r13 
.54509: movq %rcx, %r13 
.54512: pushq %r12 
.54514: pushq %rbp 
.54515: movq %rdx, %rbp 
.54518: pushq %rbx 
.54519: movq %rsi, %rbx 
.54522: subq $0x28, %rsp 
.54526: movq %rsi, 8(%rsp) 
.54531: movq %rdx, 0x18(%rsp) 
.54536: callq .18624 
.54541: movq (%rbx), %r15 
.54544: testq %r15, %r15 
.54547: je .54758 
.54553: movb $0, 0x17(%rsp) 
.54558: movq %rax, %r12 
.54561: xorl %ebx, %ebx 
.54563: movq $-1, (%rsp) 
.54571: jmp .54648 
.54576: movq 0x18(%rsp), %rax 
.54581: testq %rax, %rax 
.54584: je .54696 
.54586: movq (%rsp), %rdi 
.54590: movq %r13, %rdx 
.54593: movq %rbp, %rsi 
.54596: imulq %r13, %rdi 
.54600: addq %rax, %rdi 
.54603: callq .18992 
.54608: movl $1, %ecx 
.54613: testl %eax, %eax 
.54615: movzbl 0x17(%rsp), %eax 
.54620: cmovnel %ecx, %eax 
.54623: movb %al, 0x17(%rsp) 
.54627: movq 8(%rsp), %rax 
.54632: addq $1, %rbx 
.54636: addq %r13, %rbp 
.54639: movq (%rax, %rbx, 8), %r15 
.54643: testq %r15, %r15 
.54646: je .54704 
.54648: movq %r12, %rdx 
.54651: movq %r14, %rsi 
.54654: movq %r15, %rdi 
.54657: callq .18288 
.54662: testl %eax, %eax 
.54664: jne .54627 
.54666: movq %r15, %rdi 
.54669: callq .18624 
.54674: cmpq %r12, %rax 
.54677: je .54752 
.54679: cmpq $-1, (%rsp) 
.54684: jne .54576 
.54686: movq %rbx, (%rsp) 
.54690: jmp .54627 
.54696: movb $1, 0x17(%rsp) 
.54701: jmp .54627 
.54704: cmpb $0, 0x17(%rsp) 
.54709: movq $-2, %rax 
.54716: cmoveq (%rsp), %rax 
.54721: movq %rax, (%rsp) 
.54725: movq (%rsp), %rax 
.54729: addq $0x28, %rsp 
.54733: popq %rbx 
.54734: popq %rbp 
.54735: popq %r12 
.54737: popq %r13 
.54739: popq %r14 
.54741: popq %r15 
.54743: ret 
.54752: movq %rbx, (%rsp) 
.54756: jmp .54725 
.54758: movq $-1, (%rsp) 
.54766: jmp .54725 
