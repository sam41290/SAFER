.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.50678: nopw %cs:(%rax, %rax) 
.50688: endbr64 
.50692: movq 0x60(%rsi), %rax 
.50696: cmpq %rax, 0x60(%rdi) 
.50700: jg .50736 
.50702: jl .50728 
.50704: movq 0x68(%rsi), %rax 
.50708: subl 0x68(%rdi), %eax 
.50711: jne .50733 
.50713: movq (%rsi), %rsi 
.50716: movq (%rdi), %rdi 
.50719: jmp .19072 
.50728: movl $1, %eax 
.50733: ret 
.50736: movl $0xffffffff, %eax 
.50741: ret 
