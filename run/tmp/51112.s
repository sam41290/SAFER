.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.51112: nopl (%rax, %rax) 
.51120: endbr64 
.51124: movl 0xa8(%rdi), %eax 
.51130: movq %rsi, %rdx 
.51133: movl 0xa8(%rsi), %esi 
.51139: cmpl $3, %eax 
.51142: sete %cl 
.51145: cmpl $9, %eax 
.51148: sete %al 
.51151: orl %eax, %ecx 
.51153: cmpl $3, %esi 
.51156: sete %al 
.51159: cmpl $9, %esi 
.51162: sete %sil 
.51166: orb %sil, %al 
.51169: jne .51192 
.51171: testb %cl, %cl 
.51173: jne .51264 
.51175: movl $1, %r8d 
.51181: testb %al, %al 
.51183: je .51196 
.51185: movl %r8d, %eax 
.51188: ret 
.51192: testb %cl, %cl 
.51194: je .51175 
.51196: movq 0x80(%rdi), %rax 
.51203: cmpq %rax, 0x80(%rdx) 
.51210: jg .51264 
.51212: jl .51248 
.51214: movq 0x88(%rdi), %r8 
.51221: subl 0x88(%rdx), %r8d 
.51228: jne .51185 
.51230: movq (%rdi), %rsi 
.51233: movq (%rdx), %rdi 
.51236: jmp .19072 
.51248: movl $1, %r8d 
.51254: movl %r8d, %eax 
.51257: ret 
.51264: movl $0xffffffff, %r8d 
.51270: jmp .51185 
