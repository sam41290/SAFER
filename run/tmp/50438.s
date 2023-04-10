.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.50438: nopw %cs:(%rax, %rax) 
.50448: endbr64 
.50452: movq 0x70(%rdi), %rax 
.50456: movq %rsi, %rdx 
.50459: cmpq %rax, 0x70(%rsi) 
.50463: jg .50512 
.50465: jl .50496 
.50467: movq 0x78(%rdi), %rax 
.50471: subl 0x78(%rsi), %eax 
.50474: jne .50501 
.50476: movq (%rdi), %rsi 
.50479: movq (%rdx), %rdi 
.50482: jmp .19072 
.50496: movl $1, %eax 
.50501: ret 
.50512: movl $0xffffffff, %eax 
.50517: ret 
