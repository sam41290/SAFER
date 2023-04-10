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
.49462: nopw %cs:(%rax, %rax) 
.49472: endbr64 
.49476: movq 0x60(%rsi), %rax 
.49480: cmpq %rax, 0x60(%rdi) 
.49484: jg .49520 
.49486: jl .49512 
.49488: movq 0x68(%rsi), %rax 
.49492: subl 0x68(%rdi), %eax 
.49495: jne .49517 
.49497: movq (%rsi), %rsi 
.49500: movq (%rdi), %rdi 
.49503: jmp .29456 
.49512: movl $1, %eax 
.49517: ret 
.49520: movl $0xffffffff, %eax 
.49525: ret 
