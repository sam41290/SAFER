.91124: movzbl (%rsi), %ebp 
.91127: testb %r13b, %r13b 
.91130: jne .91408 
.91136: movq %rdx, (%rbx) 
.91139: movq 0x18(%rsp), %rax 
.91144: xorq %fs:0x28, %rax 
.91153: jne .92055 
.91159: addq $0x28, %rsp 
.91163: movl %r12d, %eax 
.91166: popq %rbx 
.91167: popq %rbp 
.91168: popq %r12 
.91170: popq %r13 
.91172: popq %r14 
.91174: popq %r15 
.91176: ret 
.91195: movl $4, %r12d 
.91201: jmp .91139 
.91203: nopl (%rax, %rax) 
.91208: testq %r15, %r15 
.91211: je .91195 
.91213: movzbl (%r12), %r13d 
.91218: testb %r13b, %r13b 
.91221: je .91195 
.91223: movsbl %r13b, %esi 
.91227: movq %r15, %rdi 
.91230: xorl %r12d, %r12d 
.91233: callq .18704 
.91238: movl $1, %edx 
.91243: testq %rax, %rax 
.91246: je .91195 
.91248: leal -0x45(%r13), %eax 
.91252: cmpb $0x2f, %al 
.91254: ja .91276 
.91256: leaq .118752(%rip), %rcx 
.91263: movzbl %al, %eax 
.91266: movslq (%rcx, %rax, 4), %rax 
.91270: addq %rcx, %rax 
.91273: jmpq *%rax 
.91276: movl $1, %ecx 
.91281: movl $0x400, %esi 
.91286: leal -0x42(%r13), %eax 
.91290: cmpb $0x35, %al 
.91292: ja .91439 
.91298: leaq .118944(%rip), %rdi 
.91305: movzbl %al, %eax 
.91308: movslq (%rdi, %rax, 4), %rax 
.91312: addq %rdi, %rax 
.91315: jmpq *%rax 
.91408: movsbl %r13b, %esi 
.91412: movq %r15, %rdi 
.91415: movq %rdx, 8(%rsp) 
.91420: callq .18704 
.91425: movq 8(%rsp), %rdx 
.91430: testq %rax, %rax 
.91433: jne .91248 
.91439: movq %rdx, (%rbx) 
.91442: orl $2, %r12d 
.91446: jmp .91139 
.92055: hlt 
