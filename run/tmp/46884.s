.44019: movq -0x38(%rbp), %rax 
.44023: xorq %fs:0x28, %rax 
.44032: jne .47274 
.44038: leaq -0x28(%rbp), %rsp 
.44042: movq %r14, %rax 
.44045: popq %rbx 
.44046: popq %r12 
.44048: popq %r13 
.44050: popq %r14 
.44052: popq %r15 
.44054: popq %rbp 
.44055: ret 
.46884: jmp .44019 
.47274: hlt 
