.84347: nopl (%rax, %rax) 
.84352: endbr64 
.84356: pushq %r15 
.84358: leaq .148768(%rip), %rax 
.84365: pushq %r14 
.84367: movq %rdx, %r14 
.84370: pushq %r13 
.84372: movq %rsi, %r13 
.84375: pushq %r12 
.84377: movq %rdi, %r12 
.84380: pushq %rbp 
.84381: pushq %rbx 
.84382: movq %r8, %rbx 
.84385: subq $0x18, %rsp 
.84389: testq %r8, %r8 
.84392: cmoveq %rax, %rbx 
.84396: movq %rcx, 8(%rsp) 
.84401: callq .18272 
.84406: subq $8, %rsp 
.84410: movq %r14, %rdx 
.84413: movq %r13, %rsi 
.84416: movl (%rax), %r15d 
.84419: movq %rax, %rbp 
.84422: leaq 8(%rbx), %rax 
.84426: movl 4(%rbx), %r9d 
.84430: pushq 0x30(%rbx) 
.84433: movl (%rbx), %r8d 
.84436: movq %r12, %rdi 
.84439: pushq 0x28(%rbx) 
.84442: pushq %rax 
.84443: movq 0x28(%rsp), %rcx 
.84448: callq .78960 
.84453: movl %r15d, (%rbp) 
.84457: addq $0x38, %rsp 
.84461: popq %rbx 
.84462: popq %rbp 
.84463: popq %r12 
.84465: popq %r13 
.84467: popq %r14 
.84469: popq %r15 
.84471: ret 
