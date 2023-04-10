.28700: nopl (%rax) 
.28704: pushq %rbp 
.28705: movq %rdi, %rbp 
.28708: movq $-1, %rcx 
.28715: movl $2, %esi 
.28720: pushq %rbx 
.28721: movq %rbp, %rdx 
.28724: subq $0x18, %rsp 
.28728: movq .148176(%rip), %r8 
.28735: movq %fs:0x28, %rax 
.28744: movq %rax, 8(%rsp) 
.28749: xorl %eax, %eax 
.28751: leaq 6(%rsp), %rdi 
.28756: callq .84352 
.28761: movzbl 6(%rsp), %edx 
.28766: cmpb %dl, (%rbp) 
.28769: je .28800 
.28771: movl $1, %eax 
.28776: movq 8(%rsp), %rcx 
.28781: xorq %fs:0x28, %rcx 
.28790: jne .28819 
.28792: addq $0x18, %rsp 
.28796: popq %rbx 
.28797: popq %rbp 
.28798: ret 
.28800: movq %rbp, %rdi 
.28803: movq %rax, %rbx 
.28806: callq .18624 
.28811: cmpq %rbx, %rax 
.28814: setne %al 
.28817: jmp .28776 
.28819: hlt 
