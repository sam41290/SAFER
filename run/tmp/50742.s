.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.50742: nopw %cs:(%rax, %rax) 
.50752: endbr64 
.50756: movq 0x80(%rdi), %rax 
.50763: movq %rsi, %rdx 
.50766: cmpq %rax, 0x80(%rsi) 
.50773: jg .50816 
.50775: jl .50808 
.50777: movq 0x88(%rdi), %rax 
.50784: subl 0x88(%rsi), %eax 
.50790: jne .50813 
.50792: movq (%rdi), %rsi 
.50795: movq (%rdx), %rdi 
.50798: jmp .19072 
.50808: movl $1, %eax 
.50813: ret 
.50816: movl $0xffffffff, %eax 
.50821: ret 
