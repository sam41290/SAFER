.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.42918: nopw %cs:(%rax, %rax) 
.42928: endbr64 
.42932: movq 0x48(%rdi), %rdx 
.42936: movq %rsi, %rax 
.42939: cmpq %rdx, 0x48(%rsi) 
.42943: jg .42976 
.42945: jne .42960 
.42947: movq (%rdi), %rsi 
.42950: movq (%rax), %rdi 
.42953: jmp .19072 
.42960: setl %al 
.42963: movzbl %al, %eax 
.42966: ret 
.42976: movl $0xffffffff, %eax 
.42981: ret 
