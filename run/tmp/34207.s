.33549: cmpb $0, .148392(%rip) 
.33556: jne .33767 
.33562: movq 0x38(%rsp), %rax 
.33567: movb $0, (%rax) 
.33570: jmp .33796 
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
.34207: movslq %eax, %rbx 
.34210: jmp .33549 
.34364: hlt 
