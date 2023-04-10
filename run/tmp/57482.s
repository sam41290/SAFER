.57482: nopw (%rax, %rax) 
.57488: endbr64 
.57492: pushq %rbp 
.57493: xorl %ebp, %ebp 
.57495: pushq %rbx 
.57496: movq %rdi, %rbx 
.57499: subq $8, %rsp 
.57503: cmpb $0x2f, (%rdi) 
.57506: sete %bpl 
.57510: callq .57664 
.57515: subq %rbx, %rax 
.57518: jmp .57534 
.57520: cmpb $0x2f, -1(%rbx, %rax) 
.57525: leaq -1(%rax), %rdx 
.57529: jne .57539 
.57531: movq %rdx, %rax 
.57534: cmpq %rbp, %rax 
.57537: ja .57520 
.57539: addq $8, %rsp 
.57543: popq %rbx 
.57544: popq %rbp 
.57545: ret 
