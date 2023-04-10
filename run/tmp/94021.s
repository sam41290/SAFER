.94021: nopw %cs:(%rax, %rax) 
.94032: pushq %r12 
.94034: pushq %rbp 
.94035: pushq %rbx 
.94036: movq %rdi, %rbx 
.94039: leaq .105200(%rip), %rdi 
.94046: callq .18192 
.94051: movq %rax, %rbp 
.94054: testq %rax, %rax 
.94057: je .94176 
.94059: cmpb $0, 8(%rbx) 
.94063: jne .94144 
.94065: movq %rbp, %rdi 
.94068: callq .93520 
.94073: movq %rax, %r12 
.94076: testq %rax, %rax 
.94079: je .94131 
.94081: xorl %edi, %edi 
.94083: cmpb $0, 8(%rbx) 
.94087: je .94093 
.94089: leaq 9(%rbx), %rdi 
.94093: callq .93328 
.94098: testl %eax, %eax 
.94100: je .94200 
.94102: callq .18272 
.94107: movl (%rax), %ebp 
.94109: movq %rax, %rbx 
.94112: cmpq $1, %r12 
.94116: je .94126 
.94118: movq %r12, %rdi 
.94121: callq .93376 
.94126: movl %ebp, (%rbx) 
.94128: xorl %r12d, %r12d 
.94131: movq %r12, %rax 
.94134: popq %rbx 
.94135: popq %rbp 
.94136: popq %r12 
.94138: ret 
.94144: leaq 9(%rbx), %rdi 
.94148: movq %rax, %rsi 
.94151: movl $1, %r12d 
.94157: callq .19072 
.94162: testl %eax, %eax 
.94164: jne .94065 
.94166: movq %r12, %rax 
.94169: popq %rbx 
.94170: popq %rbp 
.94171: popq %r12 
.94173: ret 
.94176: cmpb $0, 8(%rbx) 
.94180: movl $1, %r12d 
.94186: jne .94065 
.94188: movq %r12, %rax 
.94191: popq %rbx 
.94192: popq %rbp 
.94193: popq %r12 
.94195: ret 
.94200: callq .19216 
.94205: movq %r12, %rax 
.94208: popq %rbx 
.94209: popq %rbp 
.94210: popq %r12 
.94212: ret 
