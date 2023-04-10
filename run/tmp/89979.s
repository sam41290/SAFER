.89713: movq 0x18(%rsp), %rax 
.89718: xorq %fs:0x28, %rax 
.89727: jne .90631 
.89733: addq $0x28, %rsp 
.89737: movl %r12d, %eax 
.89740: popq %rbx 
.89741: popq %rbp 
.89742: popq %r12 
.89744: popq %r13 
.89746: popq %r14 
.89748: popq %r15 
.89750: ret 
.89771: movl $4, %r12d 
.89777: jmp .89713 
.89790: movzbl (%rsp), %ebp 
.89794: testb %r13b, %r13b 
.89797: je .89771 
.89799: movsbl %r13b, %esi 
.89803: movq %r15, %rdi 
.89806: xorl %r12d, %r12d 
.89809: callq .18704 
.89814: movl $1, %edx 
.89819: testq %rax, %rax 
.89822: je .89771 
.89824: leal -0x45(%r13), %eax 
.89828: cmpb $0x2f, %al 
.89830: ja .89852 
.89832: leaq .118040(%rip), %rcx 
.89839: movzbl %al, %eax 
.89842: movslq (%rcx, %rax, 4), %rax 
.89846: addq %rcx, %rax 
.89849: jmpq *%rax 
.89852: movl $1, %ecx 
.89857: movl $0x400, %esi 
.89862: leal -0x42(%r13), %eax 
.89866: cmpb $0x35, %al 
.89868: ja .90015 
.89874: leaq .118232(%rip), %rdi 
.89881: movzbl %al, %eax 
.89884: movslq (%rdi, %rax, 4), %rax 
.89888: addq %rdi, %rax 
.89891: jmpq *%rax 
.89979: nopl (%rax, %rax) 
.89984: movsbl %r13b, %esi 
.89988: movq %r15, %rdi 
.89991: movq %rdx, 8(%rsp) 
.89996: callq .18704 
.90001: movq 8(%rsp), %rdx 
.90006: testq %rax, %rax 
.90009: jne .89824 
.90015: movq %rdx, (%rbx) 
.90018: orl $2, %r12d 
.90022: jmp .89713 
.90631: hlt 
