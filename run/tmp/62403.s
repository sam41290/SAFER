.62403: nopw %cs:(%rax, %rax) 
.62414: nop 
.62416: endbr64 
.62420: pushq %r15 
.62422: pushq %r14 
.62424: pushq %r13 
.62426: pushq %r12 
.62428: pushq %rbp 
.62429: pushq %rbx 
.62430: subq $8, %rsp 
.62434: movq (%rdi), %r14 
.62437: cmpq %r14, 8(%rdi) 
.62441: jbe .62531 
.62443: movq %rdi, %r15 
.62446: movq %rsi, %rbp 
.62449: movq %rdx, %r13 
.62452: xorl %r12d, %r12d 
.62455: movq (%r14), %rdi 
.62458: testq %rdi, %rdi 
.62461: jne .62496 
.62463: addq $0x10, %r14 
.62467: cmpq %r14, 8(%r15) 
.62471: ja .62455 
.62473: addq $8, %rsp 
.62477: movq %r12, %rax 
.62480: popq %rbx 
.62481: popq %rbp 
.62482: popq %r12 
.62484: popq %r13 
.62486: popq %r14 
.62488: popq %r15 
.62490: ret 
.62496: movq %r14, %rbx 
.62499: jmp .62520 
.62504: movq 8(%rbx), %rbx 
.62508: addq $1, %r12 
.62512: testq %rbx, %rbx 
.62515: je .62463 
.62517: movq (%rbx), %rdi 
.62520: movq %r13, %rsi 
.62523: callq *%rbp 
.62525: testb %al, %al 
.62527: jne .62504 
.62529: jmp .62473 
.62531: xorl %r12d, %r12d 
.62534: jmp .62473 
