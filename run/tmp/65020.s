.65020: nopl (%rax) 
.65024: endbr64 
.65028: pushq %rbp 
.65029: movq %rdi, %rbp 
.65032: pushq %rbx 
.65033: movq %rsi, %rbx 
.65036: subq $8, %rsp 
.65040: movq (%rdi), %rdi 
.65043: callq .94976 
.65048: xorl %edx, %edx 
.65050: xorq 8(%rbp), %rax 
.65054: addq $8, %rsp 
.65058: divq %rbx 
.65061: popq %rbx 
.65062: popq %rbp 
.65063: movq %rdx, %rax 
.65066: ret 
