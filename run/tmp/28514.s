.28514: nopw %cs:(%rax, %rax) 
.28525: nopl (%rax) 
.28528: cmpq $0, .148400(%rip) 
.28536: pushq %rbx 
.28537: je .28573 
.28539: xorl %ebx, %ebx 
.28541: nopl (%rax) 
.28544: movq .148384(%rip), %rax 
.28551: movq (%rax, %rbx, 8), %rdi 
.28555: addq $1, %rbx 
.28559: callq .28448 
.28564: cmpq %rbx, .148400(%rip) 
.28571: ja .28544 
.28573: movq $0, .148400(%rip) 
.28584: popq %rbx 
.28585: movb $0, .148393(%rip) 
.28592: movb $0, .148324(%rip) 
.28599: movl $0, .148320(%rip) 
.28609: movl $0, .148316(%rip) 
.28619: movl $0, .148312(%rip) 
.28629: movl $0, .148304(%rip) 
.28639: movl $0, .148300(%rip) 
.28649: movl $0, .148296(%rip) 
.28659: movl $0, .148308(%rip) 
.28669: movl $0, .148292(%rip) 
.28679: movl $0, .148288(%rip) 
.28689: movl $0, .148284(%rip) 
.28699: ret 
