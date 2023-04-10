.78725: nopw %cs:(%rax, %rax) 
.78735: nop 
.78736: pushq %rbp 
.78737: movq %rdi, %rbp 
.78740: pushq %rbx 
.78741: movl %esi, %ebx 
.78743: subq $8, %rsp 
.78747: callq .95040 
.78752: movzbl (%rax), %edx 
.78755: andl $0xffffffdf, %edx 
.78758: cmpb $0x55, %dl 
.78761: jne .78840 
.78763: movzbl 1(%rax), %edx 
.78767: andl $0xffffffdf, %edx 
.78770: cmpb $0x54, %dl 
.78773: jne .78869 
.78775: movzbl 2(%rax), %edx 
.78779: andl $0xffffffdf, %edx 
.78782: cmpb $0x46, %dl 
.78785: jne .78869 
.78787: cmpb $0x2d, 3(%rax) 
.78791: jne .78869 
.78793: cmpb $0x38, 4(%rax) 
.78797: jne .78869 
.78799: cmpb $0, 5(%rax) 
.78803: jne .78869 
.78805: cmpb $0x60, (%rbp) 
.78809: leaq .115285(%rip), %rax 
.78816: leaq .115274(%rip), %rdx 
.78823: cmovneq %rdx, %rax 
.78827: addq $8, %rsp 
.78831: popq %rbx 
.78832: popq %rbp 
.78833: ret 
.78840: cmpb $0x47, %dl 
.78843: jne .78869 
.78845: movzbl 1(%rax), %edx 
.78849: andl $0xffffffdf, %edx 
.78852: cmpb $0x42, %dl 
.78855: jne .78869 
.78857: cmpb $0x31, 2(%rax) 
.78861: jne .78869 
.78863: cmpb $0x38, 3(%rax) 
.78867: je .78904 
.78869: cmpl $9, %ebx 
.78872: leaq .115272(%rip), %rax 
.78879: leaq .118747(%rip), %rdx 
.78886: cmovneq %rdx, %rax 
.78890: addq $8, %rsp 
.78894: popq %rbx 
.78895: popq %rbp 
.78896: ret 
.78904: cmpb $0x30, 4(%rax) 
.78908: jne .78869 
.78910: cmpb $0x33, 5(%rax) 
.78914: jne .78869 
.78916: cmpb $0x30, 6(%rax) 
.78920: jne .78869 
.78922: cmpb $0, 7(%rax) 
.78926: jne .78869 
.78928: cmpb $0x60, (%rbp) 
.78932: leaq .115278(%rip), %rax 
.78939: leaq .115282(%rip), %rdx 
.78946: cmovneq %rdx, %rax 
.78950: addq $8, %rsp 
.78954: popq %rbx 
.78955: popq %rbp 
.78956: ret 
