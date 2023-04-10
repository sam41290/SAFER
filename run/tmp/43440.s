.43390: movq 0x18(%rsp), %rbx 
.43395: xorq %fs:0x28, %rbx 
.43404: jne .43452 
.43406: addq $0x28, %rsp 
.43410: popq %rbx 
.43411: popq %rbp 
.43412: ret 
.43440: movl $0, %edx 
.43445: testl %eax, %eax 
.43447: cmovsl %edx, %eax 
.43450: jmp .43390 
.43452: hlt 
