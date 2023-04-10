.33438: nop 
.33440: movq %rbp, %rdi 
.33443: callq .18624 
.33448: movq %rbp, 0x18(%rsp) 
.33453: movq %rax, %r12 
.33456: cmpq $0, 0x20(%rsp) 
.33462: je .33584 
.33464: callq .18608 
.33469: cmpq $1, %rax 
.33473: ja .34192 
.33479: movq 0x18(%rsp), %rbx 
.33484: leaq (%rbx, %r12), %rbp 
.33488: cmpq %rbx, %rbp 
.33491: jbe .34336 
.33497: callq .19840 
.33502: movq (%rax), %rcx 
.33505: movq %rbx, %rax 
.33508: xorl %ebx, %ebx 
.33510: nopw %cs:(%rax, %rax) 
.33520: movzbl (%rax), %edx 
.33523: movzwl (%rcx, %rdx, 2), %edx 
.33527: andw $0x4000, %dx 
.33532: cmpw $1, %dx 
.33536: sbbq $-1, %rbx 
.33540: addq $1, %rax 
.33544: cmpq %rax, %rbp 
.33547: jne .33520 
.33549: cmpb $0, .148392(%rip) 
.33556: jne .33767 
.33562: movq 0x38(%rsp), %rax 
.33567: movb $0, (%rax) 
.33570: jmp .33796 
.33584: cmpb $0, .148392(%rip) 
.33591: jne .33767 
.33597: movq 0x38(%rsp), %rax 
.33602: movb $0, (%rax) 
.33605: jmp .33804 
.33767: movzbl 0x2f(%rsp), %eax 
.33772: xorl $1, %eax 
.33775: andb .148393(%rip), %al 
.33781: movq 0x38(%rsp), %rsi 
.33786: cmpq $0, 0x20(%rsp) 
.33792: movb %al, (%rsi) 
.33794: je .33804 
.33796: movq 0x20(%rsp), %rax 
.33801: movq %rbx, (%rax) 
.33804: movq 0x30(%rsp), %rax 
.33809: movq 0x18(%rsp), %rsi 
.33814: movq %rsi, (%rax) 
.33817: movq 0x58(%rsp), %rax 
.33822: xorq %fs:0x28, %rax 
.33831: jne .34364 
.33837: addq $0x68, %rsp 
.33841: movq %r12, %rax 
.33844: popq %rbx 
.33845: popq %rbp 
.33846: popq %r12 
.33848: popq %r13 
.33850: popq %r14 
.33852: popq %r15 
.33854: ret 
.34192: movq 0x18(%rsp), %rdi 
.34197: xorl %edx, %edx 
.34199: movq %r12, %rsi 
.34202: callq .70832 
.34207: movslq %eax, %rbx 
.34210: jmp .33549 
.34336: xorl %ebx, %ebx 
.34338: jmp .33549 
.34364: hlt 
