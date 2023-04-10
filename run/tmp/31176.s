.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.31176: nopl (%rax, %rax) 
.31184: endbr64 
.31188: movl 0xa8(%rdi), %eax 
.31194: movq %rsi, %rdx 
.31197: movl 0xa8(%rsi), %esi 
.31203: cmpl $3, %eax 
.31206: sete %cl 
.31209: cmpl $9, %eax 
.31212: sete %al 
.31215: orl %eax, %ecx 
.31217: cmpl $3, %esi 
.31220: sete %al 
.31223: cmpl $9, %esi 
.31226: sete %sil 
.31230: orb %sil, %al 
.31233: jne .31256 
.31235: testb %cl, %cl 
.31237: jne .31280 
.31239: movl $1, %r8d 
.31245: testb %al, %al 
.31247: je .31260 
.31249: movl %r8d, %eax 
.31252: ret 
.31256: testb %cl, %cl 
.31258: je .31239 
.31260: movq (%rdi), %rsi 
.31263: movq (%rdx), %rdi 
.31266: jmp .19072 
.31280: movl $0xffffffff, %r8d 
.31286: jmp .31249 
