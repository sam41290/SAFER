.19882: hlt 
.60363: nopl (%rax, %rax) 
.60368: pushq %rbx 
.60369: movq %rdi, %rbx 
.60372: movq %rsi, %rdi 
.60375: movq 0x10(%rbx), %rsi 
.60379: callq *0x30(%rbx) 
.60382: cmpq %rax, 0x10(%rbx) 
.60386: jbe .19882 
.60392: shlq $4, %rax 
.60396: addq (%rbx), %rax 
.60399: popq %rbx 
.60400: ret 
