.94972: nopl (%rax) 
.94976: endbr64 
.94980: movsbq (%rdi), %rcx 
.94984: testb %cl, %cl 
.94986: je .95024 
.94988: xorl %eax, %eax 
.94990: nop 
.94992: rolq $9, %rax 
.94996: addq $1, %rdi 
.95000: addq %rcx, %rax 
.95003: movsbq (%rdi), %rcx 
.95007: testb %cl, %cl 
.95009: jne .94992 
.95011: xorl %edx, %edx 
.95013: divq %rsi 
.95016: movq %rdx, %r8 
.95019: movq %r8, %rax 
.95022: ret 
.95024: xorl %r8d, %r8d 
.95027: movq %r8, %rax 
.95030: ret 
