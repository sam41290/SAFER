.26665: nopl (%rax) 
.26672: leaq .143976(%rip), %rdi 
.26679: leaq .143976(%rip), %rsi 
.26686: subq %rdi, %rsi 
.26689: movq %rsi, %rax 
.26692: shrq $0x3f, %rsi 
.26696: sarq $3, %rax 
.26700: addq %rax, %rsi 
.26703: sarq $1, %rsi 
.26706: je .26728 
.26708: movq .143336(%rip), %rax 
.26715: testq %rax, %rax 
.26718: je .26728 
.26720: jmpq *%rax 
.26728: ret 
