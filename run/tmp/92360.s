.92360: nopl (%rax, %rax) 
.92368: endbr64 
.92372: pushq %r13 
.92374: movq %rsi, %r13 
.92377: pushq %r12 
.92379: pushq %rbp 
.92380: movq %rdx, %rbp 
.92383: pushq %rbx 
.92384: movq %rdi, %rbx 
.92387: subq $0x18, %rsp 
.92391: movq %fs:0x28, %rax 
.92400: movq %rax, 8(%rsp) 
.92405: xorl %eax, %eax 
.92407: testq %rdi, %rdi 
.92410: leaq 4(%rsp), %rax 
.92415: cmoveq %rax, %rbx 
.92419: movq %rbx, %rdi 
.92422: callq .18688 
.92427: movq %rax, %r12 
.92430: cmpq $-3, %rax 
.92434: jbe .92441 
.92436: testq %rbp, %rbp 
.92439: jne .92480 
.92441: movq 8(%rsp), %rax 
.92446: xorq %fs:0x28, %rax 
.92455: jne .92506 
.92457: addq $0x18, %rsp 
.92461: movq %r12, %rax 
.92464: popq %rbx 
.92465: popq %rbp 
.92466: popq %r12 
.92468: popq %r13 
.92470: ret 
.92480: xorl %edi, %edi 
.92482: callq .60240 
.92487: testb %al, %al 
.92489: jne .92441 
.92491: movzbl (%r13), %eax 
.92496: movl $1, %r12d 
.92502: movl %eax, (%rbx) 
.92504: jmp .92441 
.92506: hlt 
