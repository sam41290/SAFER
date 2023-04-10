.92581: nopw %cs:(%rax, %rax) 
.92592: movq 0x38(%rdi), %rax 
.92596: testb $1, 0x50(%rdi) 
.92600: je .92608 
.92602: movq 0x48(%rdi), %rdi 
.92606: jmpq *%rax 
.92608: movq %rsi, %rdi 
.92611: jmpq *%rax 
