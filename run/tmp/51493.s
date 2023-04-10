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
.51493: nopw %cs:(%rax, %rax) 
.51504: endbr64 
.51508: pushq %r12 
.51510: pushq %rbp 
.51511: movq %rsi, %rbp 
.51514: pushq %rbx 
.51515: movl 0xa8(%rdi), %eax 
.51521: movq %rdi, %rbx 
.51524: movl 0xa8(%rsi), %ecx 
.51530: cmpl $3, %eax 
.51533: sete %dl 
.51536: cmpl $9, %eax 
.51539: sete %al 
.51542: orl %eax, %edx 
.51544: cmpl $3, %ecx 
.51547: sete %al 
.51550: cmpl $9, %ecx 
.51553: sete %cl 
.51556: orb %cl, %al 
.51558: jne .51584 
.51560: testb %dl, %dl 
.51562: jne .51680 
.51564: movl $1, %r8d 
.51570: testb %al, %al 
.51572: je .51588 
.51574: popq %rbx 
.51575: movl %r8d, %eax 
.51578: popq %rbp 
.51579: popq %r12 
.51581: ret 
.51584: testb %dl, %dl 
.51586: je .51564 
.51588: movq (%rbx), %rdi 
.51591: movl $0x2e, %esi 
.51596: callq .18784 
.51601: movq (%rbp), %rdi 
.51605: movl $0x2e, %esi 
.51610: movq %rax, %r12 
.51613: callq .18784 
.51618: movq %rax, %rsi 
.51621: leaq .104446(%rip), %rax 
.51628: testq %rsi, %rsi 
.51631: cmoveq %rax, %rsi 
.51635: testq %r12, %r12 
.51638: cmoveq %rax, %r12 
.51642: movq %r12, %rdi 
.51645: callq .29456 
.51650: movl %eax, %r8d 
.51653: testl %eax, %eax 
.51655: jne .51574 
.51657: movq (%rbp), %rsi 
.51661: movq (%rbx), %rdi 
.51664: popq %rbx 
.51665: popq %rbp 
.51666: popq %r12 
.51668: jmp .29456 
.51680: movl $0xffffffff, %r8d 
.51686: jmp .51574 
