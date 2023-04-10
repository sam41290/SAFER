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
.42470: nopw %cs:(%rax, %rax) 
.42480: endbr64 
.42484: movl 0xa8(%rdi), %eax 
.42490: movl 0xa8(%rsi), %ecx 
.42496: cmpl $3, %eax 
.42499: sete %dl 
.42502: cmpl $9, %eax 
.42505: sete %al 
.42508: orl %eax, %edx 
.42510: cmpl $3, %ecx 
.42513: sete %al 
.42516: cmpl $9, %ecx 
.42519: sete %cl 
.42522: orb %cl, %al 
.42524: jne .42544 
.42526: testb %dl, %dl 
.42528: jne .42592 
.42530: movl $1, %r8d 
.42536: testb %al, %al 
.42538: je .42548 
.42540: movl %r8d, %eax 
.42543: ret 
.42544: testb %dl, %dl 
.42546: je .42530 
.42548: movq 0x48(%rsi), %rax 
.42552: cmpq %rax, 0x48(%rdi) 
.42556: jg .42592 
.42558: jne .42576 
.42560: movq (%rsi), %rsi 
.42563: movq (%rdi), %rdi 
.42566: jmp .29456 
.42576: setl %r8b 
.42580: movzbl %r8b, %r8d 
.42584: movl %r8d, %eax 
.42587: ret 
.42592: movl $0xffffffff, %r8d 
.42598: jmp .42540 
