.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.50968: nopl (%rax, %rax) 
.50976: endbr64 
.50980: movl 0xa8(%rdi), %eax 
.50986: movq %rsi, %rdx 
.50989: movl 0xa8(%rsi), %esi 
.50995: cmpl $3, %eax 
.50998: sete %cl 
.51001: cmpl $9, %eax 
.51004: sete %al 
.51007: orl %eax, %ecx 
.51009: cmpl $3, %esi 
.51012: sete %al 
.51015: cmpl $9, %esi 
.51018: sete %sil 
.51022: orb %sil, %al 
.51025: jne .51048 
.51027: testb %cl, %cl 
.51029: jne .51104 
.51031: movl $1, %r8d 
.51037: testb %al, %al 
.51039: je .51052 
.51041: movl %r8d, %eax 
.51044: ret 
.51048: testb %cl, %cl 
.51050: je .51031 
.51052: movq 0x70(%rdi), %rax 
.51056: cmpq %rax, 0x70(%rdx) 
.51060: jg .51104 
.51062: jl .51088 
.51064: movq 0x78(%rdi), %r8 
.51068: subl 0x78(%rdx), %r8d 
.51072: jne .51041 
.51074: movq (%rdi), %rsi 
.51077: movq (%rdx), %rdi 
.51080: jmp .19072 
.51088: movl $1, %r8d 
.51094: movl %r8d, %eax 
.51097: ret 
.51104: movl $0xffffffff, %r8d 
.51110: jmp .51041 
