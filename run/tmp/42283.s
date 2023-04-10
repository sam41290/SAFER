.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.42283: nopl (%rax, %rax) 
.42288: endbr64 
.42292: movl 0xa8(%rdi), %edx 
.42298: movq %rsi, %rax 
.42301: movl 0xa8(%rsi), %esi 
.42307: cmpl $3, %edx 
.42310: sete %cl 
.42313: cmpl $9, %edx 
.42316: sete %dl 
.42319: orl %edx, %ecx 
.42321: cmpl $3, %esi 
.42324: sete %dl 
.42327: cmpl $9, %esi 
.42330: sete %sil 
.42334: orb %sil, %dl 
.42337: jne .42360 
.42339: testb %cl, %cl 
.42341: jne .42408 
.42343: movl $1, %r8d 
.42349: testb %dl, %dl 
.42351: je .42364 
.42353: movl %r8d, %eax 
.42356: ret 
.42360: testb %cl, %cl 
.42362: je .42343 
.42364: movq 0x48(%rdi), %rcx 
.42368: cmpq %rcx, 0x48(%rax) 
.42372: jg .42408 
.42374: jne .42392 
.42376: movq (%rdi), %rsi 
.42379: movq (%rax), %rdi 
.42382: jmp .19072 
.42392: setl %r8b 
.42396: movzbl %r8b, %r8d 
.42400: movl %r8d, %eax 
.42403: ret 
.42408: movl $0xffffffff, %r8d 
.42414: jmp .42353 
