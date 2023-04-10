.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.30802: nopw %cs:(%rax, %rax) 
.30813: nopl (%rax) 
.30816: endbr64 
.30820: movq 0x48(%rsi), %rax 
.30824: cmpq %rax, 0x48(%rdi) 
.30828: jg .30864 
.30830: jne .30848 
.30832: movq (%rsi), %rsi 
.30835: movq (%rdi), %rdi 
.30838: jmp .19072 
.30848: setl %al 
.30851: movzbl %al, %eax 
.30854: ret 
.30864: movl $0xffffffff, %eax 
.30869: ret 
