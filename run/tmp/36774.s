.36774: movq %rax, %r12 
.36777: movl .148244(%rip), %eax 
.36783: testl %eax, %eax 
.36785: jne .36824 
.36787: movq 0x298(%rsp), %rax 
.36795: xorq %fs:0x28, %rax 
.36804: jne .36928 
.36806: addq $0x2a8, %rsp 
.36813: movq %r12, %rax 
.36816: popq %rbx 
.36817: popq %r12 
.36819: ret 
.36824: movl 0xa8(%rbx), %edx 
.36830: movl 0x30(%rbx), %esi 
.36833: movzbl 0xb8(%rbx), %edi 
.36840: callq .31536 
.36845: movzbl %al, %eax 
.36848: addq %rax, %r12 
.36851: jmp .36787 
.36928: hlt 
