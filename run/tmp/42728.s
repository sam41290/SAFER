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
.42728: nopl (%rax, %rax) 
.42736: endbr64 
.42740: movl 0xa8(%rdi), %edx 
.42746: movq %rsi, %rax 
.42749: movl 0xa8(%rsi), %esi 
.42755: cmpl $3, %edx 
.42758: sete %cl 
.42761: cmpl $9, %edx 
.42764: sete %dl 
.42767: orl %edx, %ecx 
.42769: cmpl $3, %esi 
.42772: sete %dl 
.42775: cmpl $9, %esi 
.42778: sete %sil 
.42782: orb %sil, %dl 
.42785: jne .42808 
.42787: testb %cl, %cl 
.42789: jne .42856 
.42791: movl $1, %r8d 
.42797: testb %dl, %dl 
.42799: je .42812 
.42801: movl %r8d, %eax 
.42804: ret 
.42808: testb %cl, %cl 
.42810: je .42791 
.42812: movq 0x48(%rdi), %rcx 
.42816: cmpq %rcx, 0x48(%rax) 
.42820: jg .42856 
.42822: jne .42840 
.42824: movq (%rdi), %rsi 
.42827: movq (%rax), %rdi 
.42830: jmp .29456 
.42840: setl %r8b 
.42844: movzbl %r8b, %r8d 
.42848: movl %r8d, %eax 
.42851: ret 
.42856: movl $0xffffffff, %r8d 
.42862: jmp .42801 
