.18768: endbr64 
.18772: bnd jmpq *.142744(%rip) 
.54899: nopw %cs:(%rax, %rax) 
.54910: nop 
.54912: endbr64 
.54916: pushq %r15 
.54918: leaq .114322(%rip), %r15 
.54925: pushq %r14 
.54927: xorl %r14d, %r14d 
.54930: pushq %r13 
.54932: movq %rdx, %r13 
.54935: movl $5, %edx 
.54940: pushq %r12 
.54942: pushq %rbp 
.54943: movq %rsi, %rbp 
.54946: leaq .114301(%rip), %rsi 
.54953: pushq %rbx 
.54954: movq %rdi, %rbx 
.54957: subq $0x18, %rsp 
.54961: movq .144064(%rip), %r12 
.54968: movq %rdi, 8(%rsp) 
.54973: xorl %edi, %edi 
.54975: callq .18592 
.54980: movq %r12, %rsi 
.54983: movq %rax, %rdi 
.54986: callq .19024 
.54991: movq (%rbx), %r12 
.54994: xorl %ebx, %ebx 
.54996: testq %r12, %r12 
.54999: jne .55065 
.55001: jmp .55136 
.55008: movq %r12, %rdi 
.55011: movq %rbp, %r14 
.55014: callq .86080 
.55019: movq .144064(%rip), %rdi 
.55026: movq %r15, %rdx 
.55029: movl $1, %esi 
.55034: movq %rax, %rcx 
.55037: xorl %eax, %eax 
.55039: callq .19744 
.55044: movq 8(%rsp), %rax 
.55049: addq $1, %rbx 
.55053: addq %r13, %rbp 
.55056: movq (%rax, %rbx, 8), %r12 
.55060: testq %r12, %r12 
.55063: je .55136 
.55065: testq %rbx, %rbx 
.55068: je .55008 
.55070: movq %r13, %rdx 
.55073: movq %rbp, %rsi 
.55076: movq %r14, %rdi 
.55079: callq .18992 
.55084: testl %eax, %eax 
.55086: jne .55008 
.55088: movq %r12, %rdi 
.55091: callq .86080 
.55096: movq .144064(%rip), %rdi 
.55103: movl $1, %esi 
.55108: leaq .114330(%rip), %rdx 
.55115: movq %rax, %rcx 
.55118: xorl %eax, %eax 
.55120: callq .19744 
.55125: jmp .55044 
.55136: movq .144064(%rip), %rdi 
.55143: movq 0x28(%rdi), %rax 
.55147: cmpq 0x30(%rdi), %rax 
.55151: jae .55184 
.55153: leaq 1(%rax), %rdx 
.55157: movq %rdx, 0x28(%rdi) 
.55161: movb $0xa, (%rax) 
.55164: addq $0x18, %rsp 
.55168: popq %rbx 
.55169: popq %rbp 
.55170: popq %r12 
.55172: popq %r13 
.55174: popq %r14 
.55176: popq %r15 
.55178: ret 
.55184: addq $0x18, %rsp 
.55188: movl $0xa, %esi 
.55193: popq %rbx 
.55194: popq %rbp 
.55195: popq %r12 
.55197: popq %r13 
.55199: popq %r14 
.55201: popq %r15 
.55203: jmp .18768 
