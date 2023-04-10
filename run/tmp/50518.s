.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.50518: nopw %cs:(%rax, %rax) 
.50528: endbr64 
.50532: movq 0x80(%rsi), %rax 
.50539: cmpq %rax, 0x80(%rdi) 
.50546: jg .50592 
.50548: jl .50576 
.50550: movq 0x88(%rsi), %rax 
.50557: subl 0x88(%rdi), %eax 
.50563: jne .50581 
.50565: movq (%rsi), %rsi 
.50568: movq (%rdi), %rdi 
.50571: jmp .19072 
.50576: movl $1, %eax 
.50581: ret 
.50592: movl $0xffffffff, %eax 
.50597: ret 
