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
.49672: nopl (%rax, %rax) 
.49680: endbr64 
.49684: movl 0xa8(%rdi), %eax 
.49690: movl 0xa8(%rsi), %ecx 
.49696: cmpl $3, %eax 
.49699: sete %dl 
.49702: cmpl $9, %eax 
.49705: sete %al 
.49708: orl %eax, %edx 
.49710: cmpl $3, %ecx 
.49713: sete %al 
.49716: cmpl $9, %ecx 
.49719: sete %cl 
.49722: orb %cl, %al 
.49724: jne .49744 
.49726: testb %dl, %dl 
.49728: jne .49800 
.49730: movl $1, %r8d 
.49736: testb %al, %al 
.49738: je .49748 
.49740: movl %r8d, %eax 
.49743: ret 
.49744: testb %dl, %dl 
.49746: je .49730 
.49748: movq 0x70(%rsi), %rax 
.49752: cmpq %rax, 0x70(%rdi) 
.49756: jg .49800 
.49758: jl .49784 
.49760: movq 0x78(%rsi), %r8 
.49764: subl 0x78(%rdi), %r8d 
.49768: jne .49740 
.49770: movq (%rsi), %rsi 
.49773: movq (%rdi), %rdi 
.49776: jmp .29456 
.49784: movl $1, %r8d 
.49790: movl %r8d, %eax 
.49793: ret 
.49800: movl $0xffffffff, %r8d 
.49806: jmp .49740 
