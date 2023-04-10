.19360: endbr64 
.19364: bnd jmpq *.143040(%rip) 
.29456: pushq %r12 
.29458: movq %rsi, %r12 
.29461: pushq %rbp 
.29462: movq %rdi, %rbp 
.29465: subq $8, %rsp 
.29469: callq .18272 
.29474: movq %r12, %rsi 
.29477: movq %rbp, %rdi 
.29480: movl $0, (%rax) 
.29486: addq $8, %rsp 
.29490: popq %rbp 
.29491: popq %r12 
.29493: jmp .19360 
.49526: nopw %cs:(%rax, %rax) 
.49536: endbr64 
.49540: movl 0xa8(%rdi), %eax 
.49546: movq %rsi, %rdx 
.49549: movl 0xa8(%rsi), %esi 
.49555: cmpl $3, %eax 
.49558: sete %cl 
.49561: cmpl $9, %eax 
.49564: sete %al 
.49567: orl %eax, %ecx 
.49569: cmpl $3, %esi 
.49572: sete %al 
.49575: cmpl $9, %esi 
.49578: sete %sil 
.49582: orb %sil, %al 
.49585: jne .49608 
.49587: testb %cl, %cl 
.49589: jne .49664 
.49591: movl $1, %r8d 
.49597: testb %al, %al 
.49599: je .49612 
.49601: movl %r8d, %eax 
.49604: ret 
.49608: testb %cl, %cl 
.49610: je .49591 
.49612: movq 0x60(%rdi), %rax 
.49616: cmpq %rax, 0x60(%rdx) 
.49620: jg .49664 
.49622: jl .49648 
.49624: movq 0x68(%rdi), %r8 
.49628: subl 0x68(%rdx), %r8d 
.49632: jne .49601 
.49634: movq (%rdi), %rsi 
.49637: movq (%rdx), %rdi 
.49640: jmp .29456 
.49648: movl $1, %r8d 
.49654: movl %r8d, %eax 
.49657: ret 
.49664: movl $0xffffffff, %r8d 
.49670: jmp .49601 
