.31529: nopl (%rax) 
.31536: pushq %rbx 
.31537: movzbl %dil, %edi 
.31541: callq .31296 
.31546: movl %eax, %ebx 
.31548: testb %al, %al 
.31550: je .31587 
.31552: movq .144008(%rip), %rdi 
.31559: movq 0x28(%rdi), %rax 
.31563: cmpq 0x30(%rdi), %rax 
.31567: jae .31600 
.31569: leaq 1(%rax), %rdx 
.31573: movq %rdx, 0x28(%rdi) 
.31577: movb %bl, (%rax) 
.31579: addq $1, .147960(%rip) 
.31587: testb %bl, %bl 
.31589: popq %rbx 
.31590: setne %al 
.31593: ret 
.31600: movzbl %bl, %esi 
.31603: callq .18768 
.31608: jmp .31579 
