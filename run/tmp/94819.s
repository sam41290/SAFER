.94819: nopw %cs:(%rax, %rax) 
.94829: nopl (%rax) 
.94832: endbr64 
.94836: pushq %r12 
.94838: pushq %rbp 
.94839: movq %rdi, %rbp 
.94842: pushq %rbx 
.94843: callq .18352 
.94848: movl (%rbp), %ebx 
.94851: movq %rbp, %rdi 
.94854: movq %rax, %r12 
.94857: andl $0x20, %ebx 
.94860: callq .95104 
.94865: testl %ebx, %ebx 
.94867: jne .94904 
.94869: testl %eax, %eax 
.94871: je .94894 
.94873: testq %r12, %r12 
.94876: jne .94926 
.94878: callq .18272 
.94883: cmpl $9, (%rax) 
.94886: setne %al 
.94889: movzbl %al, %eax 
.94892: negl %eax 
.94894: popq %rbx 
.94895: popq %rbp 
.94896: popq %r12 
.94898: ret 
.94904: testl %eax, %eax 
.94906: jne .94926 
.94908: callq .18272 
.94913: movl $0, (%rax) 
.94919: movl $0xffffffff, %eax 
.94924: jmp .94894 
.94926: movl $0xffffffff, %eax 
.94931: jmp .94894 
