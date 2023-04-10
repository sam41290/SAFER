.26832: endbr64 
.26836: movq (%rsi), %rdx 
.26839: xorl %eax, %eax 
.26841: cmpq %rdx, (%rdi) 
.26844: je .26848 
.26846: ret 
.26847: nop 
.26848: movq 8(%rsi), %rax 
.26852: cmpq %rax, 8(%rdi) 
.26856: sete %al 
.26859: ret 
