.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.43136: endbr64 
.43140: movl 0xa8(%rdi), %eax 
.43146: movl 0xa8(%rsi), %ecx 
.43152: cmpl $3, %eax 
.43155: sete %dl 
.43158: cmpl $9, %eax 
.43161: sete %al 
.43164: orl %eax, %edx 
.43166: cmpl $3, %ecx 
.43169: sete %al 
.43172: cmpl $9, %ecx 
.43175: sete %cl 
.43178: orb %cl, %al 
.43180: jne .43200 
.43182: testb %dl, %dl 
.43184: jne .43256 
.43186: movl $1, %r8d 
.43192: testb %al, %al 
.43194: je .43204 
.43196: movl %r8d, %eax 
.43199: ret 
.43200: testb %dl, %dl 
.43202: je .43186 
.43204: movq 0x70(%rsi), %rax 
.43208: cmpq %rax, 0x70(%rdi) 
.43212: jg .43256 
.43214: jl .43240 
.43216: movq 0x78(%rsi), %r8 
.43220: subl 0x78(%rdi), %r8d 
.43224: jne .43196 
.43226: movq (%rsi), %rsi 
.43229: movq (%rdi), %rdi 
.43232: jmp .19072 
.43237: nopl (%rax) 
.43240: movl $1, %r8d 
.43246: movl %r8d, %eax 
.43249: ret 
.43250: nopw (%rax, %rax) 
.43256: movl $0xffffffff, %r8d 
.43262: jmp .43196 
