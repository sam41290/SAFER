.92613: nopw %cs:(%rax, %rax) 
.92624: movq 0x40(%rdi), %rax 
.92628: testb $1, 0x50(%rdi) 
.92632: je .92640 
.92634: movq 0x48(%rdi), %rdi 
.92638: jmpq *%rax 
.92640: movq %rsi, %rdi 
.92643: jmpq *%rax 
