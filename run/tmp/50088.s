.19360: endbr64 
.19364: bnd jmpq *.143040(%rip) 
.29456: pushq %r12 
.29458: movq %rsi, %r12 
.29461: pushq %rbp 
.29462: movq %rdi, %rbp 
.29465: subq $8, %rsp 
.29469: callq .18272 
.29474: movq %r12, %rsi 
.29477: movq %rbp, %rdi 
.29480: movl $0, (%rax) 
.29486: addq $8, %rsp 
.29490: popq %rbp 
.29491: popq %r12 
.29493: jmp .19360 
.50088: nopl (%rax, %rax) 
.50096: endbr64 
.50100: movl 0xa8(%rdi), %eax 
.50106: movq %rsi, %rdx 
.50109: movl 0xa8(%rsi), %esi 
.50115: cmpl $3, %eax 
.50118: sete %cl 
.50121: cmpl $9, %eax 
.50124: sete %al 
.50127: orl %eax, %ecx 
.50129: cmpl $3, %esi 
.50132: sete %al 
.50135: cmpl $9, %esi 
.50138: sete %sil 
.50142: orb %sil, %al 
.50145: jne .50168 
.50147: testb %cl, %cl 
.50149: jne .50240 
.50151: movl $1, %r8d 
.50157: testb %al, %al 
.50159: je .50172 
.50161: movl %r8d, %eax 
.50164: ret 
.50168: testb %cl, %cl 
.50170: je .50151 
.50172: movq 0x80(%rdi), %rax 
.50179: cmpq %rax, 0x80(%rdx) 
.50186: jg .50240 
.50188: jl .50224 
.50190: movq 0x88(%rdi), %r8 
.50197: subl 0x88(%rdx), %r8d 
.50204: jne .50161 
.50206: movq (%rdi), %rsi 
.50209: movq (%rdx), %rdi 
.50212: jmp .29456 
.50224: movl $1, %r8d 
.50230: movl %r8d, %eax 
.50233: ret 
.50240: movl $0xffffffff, %r8d 
.50246: jmp .50161 
