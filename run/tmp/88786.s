.19168: endbr64 
.19172: bnd jmpq *.142944(%rip) 
.88786: nopw %cs:(%rax, %rax) 
.88797: nopl (%rax) 
.88800: endbr64 
.88804: pushq %r12 
.88806: movq %rsi, %r12 
.88809: pushq %rbp 
.88810: movq %rdi, %rbp 
.88813: movq %rsi, %rdi 
.88816: subq $8, %rsp 
.88820: callq .88256 
.88825: addq $8, %rsp 
.88829: movq %r12, %rdx 
.88832: movq %rbp, %rsi 
.88835: movq %rax, %rdi 
.88838: popq %rbp 
.88839: popq %r12 
.88841: jmp .19168 
