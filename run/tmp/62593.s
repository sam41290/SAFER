.62593: nopw %cs:(%rax, %rax) 
.62604: nopl (%rax) 
.62608: endbr64 
.62612: movabsq $0x3f80000000000000, %rax 
.62622: movb $0, 0x10(%rdi) 
.62626: movq %rax, (%rdi) 
.62629: movabsq $0x3fb4fdf43f4ccccd, %rax 
.62639: movq %rax, 8(%rdi) 
.62643: ret 
