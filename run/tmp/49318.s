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
.49318: nopw %cs:(%rax, %rax) 
.49328: endbr64 
.49332: movq 0x70(%rsi), %rax 
.49336: cmpq %rax, 0x70(%rdi) 
.49340: jg .49376 
.49342: jl .49368 
.49344: movq 0x78(%rsi), %rax 
.49348: subl 0x78(%rdi), %eax 
.49351: jne .49373 
.49353: movq (%rsi), %rsi 
.49356: movq (%rdi), %rdi 
.49359: jmp .29456 
.49368: movl $1, %eax 
.49373: ret 
.49376: movl $0xffffffff, %eax 
.49381: ret 
