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
.49158: nopw %cs:(%rax, %rax) 
.49168: endbr64 
.49172: movq 0x60(%rdi), %rax 
.49176: movq %rsi, %rdx 
.49179: cmpq %rax, 0x60(%rsi) 
.49183: jg .49232 
.49185: jl .49216 
.49187: movq 0x68(%rdi), %rax 
.49191: subl 0x68(%rsi), %eax 
.49194: jne .49221 
.49196: movq (%rdi), %rsi 
.49199: movq (%rdx), %rdi 
.49202: jmp .29456 
.49216: movl $1, %eax 
.49221: ret 
.49232: movl $0xffffffff, %eax 
.49237: ret 
