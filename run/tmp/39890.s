.39890: leaq (%rbx, %rax), %r8 
.39894: movl .148244(%rip), %eax 
.39900: testl %eax, %eax 
.39902: je .39936 
.39904: movl 0xa8(%rbp), %edx 
.39910: movl 0x30(%rbp), %esi 
.39913: movzbl 0xb8(%rbp), %edi 
.39920: callq .31296 
.39925: testb %al, %al 
.39927: setne %al 
.39930: movzbl %al, %eax 
.39933: addq %rax, %r8 
.39936: movq 0x298(%rsp), %rax 
.39944: xorq %fs:0x28, %rax 
.39953: jne .40178 
.39959: addq $0x2a8, %rsp 
.39966: movq %r8, %rax 
.39969: popq %rbx 
.39970: popq %rbp 
.39971: ret 
.40178: hlt 
