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
.49073: nopw %cs:(%rax, %rax) 
.49084: nopl (%rax) 
.49088: endbr64 
.49092: movq 0x80(%rdi), %rax 
.49099: movq %rsi, %rdx 
.49102: cmpq %rax, 0x80(%rsi) 
.49109: jg .49152 
.49111: jl .49144 
.49113: movq 0x88(%rdi), %rax 
.49120: subl 0x88(%rsi), %eax 
.49126: jne .49149 
.49128: movq (%rdi), %rsi 
.49131: movq (%rdx), %rdi 
.49134: jmp .29456 
.49144: movl $1, %eax 
.49149: ret 
.49152: movl $0xffffffff, %eax 
.49157: ret 
