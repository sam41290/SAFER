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
.30870: nopw %cs:(%rax, %rax) 
.30880: endbr64 
.30884: movl 0xa8(%rdi), %eax 
.30890: movl 0xa8(%rsi), %ecx 
.30896: cmpl $3, %eax 
.30899: sete %dl 
.30902: cmpl $9, %eax 
.30905: sete %al 
.30908: orl %eax, %edx 
.30910: cmpl $3, %ecx 
.30913: sete %al 
.30916: cmpl $9, %ecx 
.30919: sete %cl 
.30922: orb %cl, %al 
.30924: jne .30944 
.30926: testb %dl, %dl 
.30928: jne .30960 
.30930: movl $1, %r8d 
.30936: testb %al, %al 
.30938: je .30948 
.30940: movl %r8d, %eax 
.30943: ret 
.30944: testb %dl, %dl 
.30946: je .30930 
.30948: movq (%rsi), %rsi 
.30951: movq (%rdi), %rdi 
.30954: jmp .29456 
.30960: movl $0xffffffff, %r8d 
.30966: jmp .30940 
