.78538: nopw (%rax, %rax) 
.78544: endbr64 
.78548: pushq %rbx 
.78549: testq %rdi, %rdi 
.78552: je .78691 
.78558: movl $0x2f, %esi 
.78563: movq %rdi, %rbx 
.78566: callq .18784 
.78571: testq %rax, %rax 
.78574: je .78651 
.78576: leaq 1(%rax), %r8 
.78580: movq %r8, %rdx 
.78583: subq %rbx, %rdx 
.78586: cmpq $6, %rdx 
.78590: jle .78651 
.78592: leaq -6(%rax), %rsi 
.78596: movl $7, %ecx 
.78601: leaq .115264(%rip), %rdi 
.78608: repe cmpsb (%rdi), (%rsi) 
.78610: seta %dl 
.78613: sbbb $0, %dl 
.78616: testb %dl, %dl 
.78618: jne .78651 
.78620: cmpb $0x6c, 1(%rax) 
.78624: jne .78672 
.78626: cmpb $0x74, 1(%r8) 
.78631: jne .78672 
.78633: cmpb $0x2d, 2(%r8) 
.78638: jne .78672 
.78640: leaq 4(%rax), %rbx 
.78644: movq %rbx, .144000(%rip) 
.78651: movq %rbx, .148480(%rip) 
.78658: movq %rbx, .144032(%rip) 
.78665: popq %rbx 
.78666: ret 
.78672: movq %r8, %rbx 
.78675: movq %rbx, .148480(%rip) 
.78682: movq %rbx, .144032(%rip) 
.78689: popq %rbx 
.78690: ret 
.78691: movq .144064(%rip), %rcx 
.78698: movl $0x37, %edx 
.78703: movl $1, %esi 
.78708: leaq .115208(%rip), %rdi 
.78715: callq .19728 
.78720: hlt 
