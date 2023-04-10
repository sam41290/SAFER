.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.50598: nopw %cs:(%rax, %rax) 
.50608: endbr64 
.50612: movq 0x60(%rdi), %rax 
.50616: movq %rsi, %rdx 
.50619: cmpq %rax, 0x60(%rsi) 
.50623: jg .50672 
.50625: jl .50656 
.50627: movq 0x68(%rdi), %rax 
.50631: subl 0x68(%rsi), %eax 
.50634: jne .50661 
.50636: movq (%rdi), %rsi 
.50639: movq (%rdx), %rdi 
.50642: jmp .19072 
.50656: movl $1, %eax 
.50661: ret 
.50672: movl $0xffffffff, %eax 
.50677: ret 
