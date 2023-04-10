.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.42982: nopw %cs:(%rax, %rax) 
.42992: endbr64 
.42996: movl 0xa8(%rdi), %eax 
.43002: movl 0xa8(%rsi), %ecx 
.43008: cmpl $3, %eax 
.43011: sete %dl 
.43014: cmpl $9, %eax 
.43017: sete %al 
.43020: orl %eax, %edx 
.43022: cmpl $3, %ecx 
.43025: sete %al 
.43028: cmpl $9, %ecx 
.43031: sete %cl 
.43034: orb %cl, %al 
.43036: jne .43056 
.43038: testb %dl, %dl 
.43040: jne .43128 
.43042: movl $1, %r8d 
.43048: testb %al, %al 
.43050: je .43060 
.43052: movl %r8d, %eax 
.43055: ret 
.43056: testb %dl, %dl 
.43058: je .43042 
.43060: movq 0x80(%rsi), %rax 
.43067: cmpq %rax, 0x80(%rdi) 
.43074: jg .43128 
.43076: jl .43112 
.43078: movq 0x88(%rsi), %r8 
.43085: subl 0x88(%rdi), %r8d 
.43092: jne .43052 
.43094: movq (%rsi), %rsi 
.43097: movq (%rdi), %rdi 
.43100: jmp .19072 
.43112: movl $1, %r8d 
.43118: movl %r8d, %eax 
.43121: ret 
.43128: movl $0xffffffff, %r8d 
.43134: jmp .43052 
