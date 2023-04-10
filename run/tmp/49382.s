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
.49382: nopw %cs:(%rax, %rax) 
.49392: endbr64 
.49396: movq 0x70(%rdi), %rax 
.49400: movq %rsi, %rdx 
.49403: cmpq %rax, 0x70(%rsi) 
.49407: jg .49456 
.49409: jl .49440 
.49411: movq 0x78(%rdi), %rax 
.49415: subl 0x78(%rsi), %eax 
.49418: jne .49445 
.49420: movq (%rdi), %rsi 
.49423: movq (%rdx), %rdi 
.49426: jmp .29456 
.49440: movl $1, %eax 
.49445: ret 
.49456: movl $0xffffffff, %eax 
.49461: ret 
