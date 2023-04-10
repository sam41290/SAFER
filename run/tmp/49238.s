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
.49238: nopw %cs:(%rax, %rax) 
.49248: endbr64 
.49252: movq 0x80(%rsi), %rax 
.49259: cmpq %rax, 0x80(%rdi) 
.49266: jg .49312 
.49268: jl .49296 
.49270: movq 0x88(%rsi), %rax 
.49277: subl 0x88(%rdi), %eax 
.49283: jne .49301 
.49285: movq (%rsi), %rsi 
.49288: movq (%rdi), %rdi 
.49291: jmp .29456 
.49296: movl $1, %eax 
.49301: ret 
.49312: movl $0xffffffff, %eax 
.49317: ret 
