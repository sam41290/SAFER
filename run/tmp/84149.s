.84149: nopw %cs:(%rax, %rax) 
.84160: endbr64 
.84164: testq %rdi, %rdi 
.84167: leaq .148768(%rip), %rax 
.84174: cmoveq %rax, %rdi 
.84178: movl %esi, (%rdi) 
.84180: ret 
