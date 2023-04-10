.89505: nopw %cs:(%rax, %rax) 
.89515: nopl (%rax, %rax) 
.89520: endbr64 
.89524: pushq %r15 
.89526: pushq %r14 
.89528: pushq %r13 
.89530: pushq %r12 
.89532: pushq %rbp 
.89533: pushq %rbx 
.89534: subq $0x28, %rsp 
.89538: movq %fs:0x28, %rax 
.89547: movq %rax, 0x18(%rsp) 
.89552: xorl %eax, %eax 
.89554: cmpl $0x24, %edx 
.89557: ja .90600 
.89563: movq %rsi, %rbp 
.89566: testq %rsi, %rsi 
.89569: leaq 0x10(%rsp), %rax 
.89574: movq %rdi, %r12 
.89577: movl %edx, 8(%rsp) 
.89581: cmoveq %rax, %rbp 
.89585: movq %rcx, %rbx 
.89588: movq %r8, %r15 
.89591: callq .18272 
.89596: movl $0, (%rax) 
.89602: movq %rax, %r13 
.89605: movzbl (%r12), %r14d 
.89610: callq .19840 
.89615: movl 8(%rsp), %edx 
.89619: movq (%rax), %rsi 
.89622: movq %r12, %rax 
.89625: jmp .89641 
.89632: movzbl 1(%rax), %r14d 
.89637: addq $1, %rax 
.89641: movzbl %r14b, %ecx 
.89645: testb $0x20, 1(%rsi, %rcx, 2) 
.89650: jne .89632 
.89652: cmpb $0x2d, %r14b 
.89656: je .89771 
.89658: movq %rbp, %rsi 
.89661: movq %r12, %rdi 
.89664: callq .19600 
.89669: movq (%rbp), %r14 
.89673: movq %rax, %rdx 
.89676: cmpq %r12, %r14 
.89679: je .89784 
.89681: movl (%r13), %eax 
.89685: testl %eax, %eax 
.89687: jne .89760 
.89689: xorl %r12d, %r12d 
.89692: testq %r15, %r15 
.89695: je .89710 
.89697: movzbl (%r14), %r13d 
.89701: testb %r13b, %r13b 
.89704: jne .89984 
.89710: movq %rdx, (%rbx) 
.89713: movq 0x18(%rsp), %rax 
.89718: xorq %fs:0x28, %rax 
.89727: jne .90631 
.89733: addq $0x28, %rsp 
.89737: movl %r12d, %eax 
.89740: popq %rbx 
.89741: popq %rbp 
.89742: popq %r12 
.89744: popq %r13 
.89746: popq %r14 
.89748: popq %r15 
.89750: ret 
.89760: movl $1, %r12d 
.89766: cmpl $0x22, %eax 
.89769: je .89692 
.89771: movl $4, %r12d 
.89777: jmp .89713 
.89784: testq %r15, %r15 
.89787: je .89771 
.89789: movzbl (%r12), %r13d 
.89794: testb %r13b, %r13b 
.89797: je .89771 
.89799: movsbl %r13b, %esi 
.89803: movq %r15, %rdi 
.89806: xorl %r12d, %r12d 
.89809: callq .18704 
.89814: movl $1, %edx 
.89819: testq %rax, %rax 
.89822: je .89771 
.89824: leal -0x45(%r13), %eax 
.89828: cmpb $0x2f, %al 
.89830: ja .89852 
.89832: leaq .118040(%rip), %rcx 
.89839: movzbl %al, %eax 
.89842: movslq (%rcx, %rax, 4), %rax 
.89846: addq %rcx, %rax 
.89849: jmpq *%rax 
.89852: movl $1, %ecx 
.89857: movl $0x400, %esi 
.89862: leal -0x42(%r13), %eax 
.89866: cmpb $0x35, %al 
.89868: ja .90015 
.89874: leaq .118232(%rip), %rdi 
.89881: movzbl %al, %eax 
.89884: movslq (%rdi, %rax, 4), %rax 
.89888: addq %rdi, %rax 
.89891: jmpq *%rax 
.89934: addb %bh, (%rcx, %rbp, 2) 
.89937: je .90439 
.89943: cmpb $0x42, %al 
.89945: je .90585 
.89951: leal -0x45(%r13), %eax 
.89955: cmpb $0x2f, %al 
.89957: ja .90015 
.89959: leaq .118448(%rip), %rcx 
.89966: movzbl %al, %eax 
.89969: movslq (%rcx, %rax, 4), %rax 
.89973: addq %rcx, %rax 
.89976: jmpq *%rax 
.89984: movsbl %r13b, %esi 
.89988: movq %r15, %rdi 
.89991: movq %rdx, 8(%rsp) 
.89996: callq .18704 
.90001: movq 8(%rsp), %rdx 
.90006: testq %rax, %rax 
.90009: jne .89824 
.90015: movq %rdx, (%rbx) 
.90018: orl $2, %r12d 
.90022: jmp .89713 
.90283: movl $1, %ecx 
.90288: addq %r14, %rcx 
.90291: movl %r12d, %eax 
.90294: orl $2, %eax 
.90297: movq %rcx, (%rbp) 
.90301: cmpb $0, (%rcx) 
.90304: cmovnel %eax, %r12d 
.90308: jmp .89710 
.90439: xorl %ecx, %ecx 
.90441: cmpb $0x42, 2(%r14) 
.90446: movl $0x400, %esi 
.90451: sete %cl 
.90454: leal 1(%rcx, %rcx), %ecx 
.90458: jmp .89862 
.90585: movl $2, %ecx 
.90590: movl $0x3e8, %esi 
.90595: jmp .89862 
.90600: leaq .118640(%rip), %rcx 
.90607: movl $0x60, %edx 
.90612: leaq .117984(%rip), %rsi 
.90619: leaq .118000(%rip), %rdi 
.90626: hlt 
.90631: hlt 
