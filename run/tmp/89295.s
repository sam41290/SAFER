.89295: nop 
.89296: endbr64 
.89300: pushq %r14 
.89302: pushq %r13 
.89304: movabsq $0x1000401001, %r13 
.89314: pushq %r12 
.89316: pushq %rbp 
.89317: xorl %ebp, %ebp 
.89319: pushq %rbx 
.89320: subq $0x10, %rsp 
.89324: movq %fs:0x28, %rax 
.89333: movq %rax, 8(%rsp) 
.89338: xorl %eax, %eax 
.89340: movq $0x22, (%rsp) 
.89348: movq %rsp, %r12 
.89351: callq .18272 
.89356: movq %rax, %rbx 
.89359: nop 
.89360: movq %rbp, %rdi 
.89363: movq %r12, %rsi 
.89366: callq .88608 
.89371: movq (%rsp), %rsi 
.89375: movq %rax, %rdi 
.89378: movq %rax, %rbp 
.89381: leaq -2(%rax, %rsi), %r14 
.89386: subq $1, %rsi 
.89390: movb $0, (%r14) 
.89394: movl $0, (%rbx) 
.89400: callq .19680 
.89405: testl %eax, %eax 
.89407: jne .89456 
.89409: cmpb $0, (%r14) 
.89413: jne .89360 
.89415: movq 8(%rsp), %rax 
.89420: xorq %fs:0x28, %rax 
.89429: jne .89500 
.89431: addq $0x10, %rsp 
.89435: movq %rbp, %rax 
.89438: popq %rbx 
.89439: popq %rbp 
.89440: popq %r12 
.89442: popq %r13 
.89444: popq %r14 
.89446: ret 
.89456: movl (%rbx), %r14d 
.89459: cmpl $0x24, %r14d 
.89463: jbe .89488 
.89465: movq %rbp, %rdi 
.89468: xorl %ebp, %ebp 
.89470: callq .18128 
.89475: movl %r14d, (%rbx) 
.89478: jmp .89415 
.89488: btq %r14, %r13 
.89492: jb .89360 
.89498: jmp .89465 
.89500: hlt 
