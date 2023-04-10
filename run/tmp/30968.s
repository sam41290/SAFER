.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.30968: nopl (%rax, %rax) 
.30976: endbr64 
.30980: movl 0xa8(%rdi), %eax 
.30986: movl 0xa8(%rsi), %ecx 
.30992: cmpl $3, %eax 
.30995: sete %dl 
.30998: cmpl $9, %eax 
.31001: sete %al 
.31004: orl %eax, %edx 
.31006: cmpl $3, %ecx 
.31009: sete %al 
.31012: cmpl $9, %ecx 
.31015: sete %cl 
.31018: orb %cl, %al 
.31020: jne .31040 
.31022: testb %dl, %dl 
.31024: jne .31056 
.31026: movl $1, %r8d 
.31032: testb %al, %al 
.31034: je .31044 
.31036: movl %r8d, %eax 
.31039: ret 
.31040: testb %dl, %dl 
.31042: je .31026 
.31044: movq (%rsi), %rsi 
.31047: movq (%rdi), %rdi 
.31050: jmp .19072 
.31056: movl $0xffffffff, %r8d 
.31062: jmp .31036 
