.30702: nop 
.30704: pushq %r13 
.30706: pushq %r12 
.30708: movq %rsi, %r12 
.30711: movq %rdx, %rsi 
.30714: pushq %rbx 
.30715: movl %edi, %ebx 
.30717: movl $4, %edi 
.30722: callq .85312 
.30727: movq %rax, %r13 
.30730: callq .18272 
.30735: xorl %edi, %edi 
.30737: movq %r13, %rcx 
.30740: movq %r12, %rdx 
.30743: movl (%rax), %esi 
.30745: xorl %eax, %eax 
.30747: callq .19552 
.30752: testb %bl, %bl 
.30754: je .30776 
.30756: movl $2, .147984(%rip) 
.30766: popq %rbx 
.30767: popq %r12 
.30769: popq %r13 
.30771: ret 
.30776: movl .147984(%rip), %eax 
.30782: testl %eax, %eax 
.30784: jne .30766 
.30786: movl $1, .147984(%rip) 
.30796: popq %rbx 
.30797: popq %r12 
.30799: popq %r13 
.30801: ret 
