.68693: nopw %cs:(%rax, %rax) 
.68704: endbr64 
.68708: pushq %r12 
.68710: pushq %rbp 
.68711: movq %rdi, %rbp 
.68714: pushq %rbx 
.68715: movq .148472(%rip), %rbx 
.68722: testq %rbx, %rbx 
.68725: je .68784 
.68727: movzbl (%rdi), %r12d 
.68731: jmp .68745 
.68736: movq 8(%rbx), %rbx 
.68740: testq %rbx, %rbx 
.68743: je .68784 
.68745: cmpb %r12b, 0x10(%rbx) 
.68749: jne .68736 
.68751: leaq 0x10(%rbx), %rdi 
.68755: movq %rbp, %rsi 
.68758: callq .19072 
.68763: testl %eax, %eax 
.68765: jne .68736 
.68767: movq %rbx, %r12 
.68770: popq %rbx 
.68771: popq %rbp 
.68772: movq %r12, %rax 
.68775: popq %r12 
.68777: ret 
.68784: movq .148464(%rip), %rbx 
.68791: testq %rbx, %rbx 
.68794: je .68856 
.68796: movzbl (%rbp), %r12d 
.68801: jmp .68817 
.68808: movq 8(%rbx), %rbx 
.68812: testq %rbx, %rbx 
.68815: je .68856 
.68817: cmpb %r12b, 0x10(%rbx) 
.68821: jne .68808 
.68823: leaq 0x10(%rbx), %rdi 
.68827: movq %rbp, %rsi 
.68830: callq .19072 
.68835: testl %eax, %eax 
.68837: jne .68808 
.68839: xorl %r12d, %r12d 
.68842: popq %rbx 
.68843: popq %rbp 
.68844: movq %r12, %rax 
.68847: popq %r12 
.68849: ret 
.68856: movq %rbp, %rdi 
.68859: callq .19120 
.68864: movq %rbp, %rdi 
.68867: movq %rax, %r12 
.68870: callq .18624 
.68875: leaq 0x18(%rax), %rdi 
.68879: andq $0xfffffffffffffff8, %rdi 
.68883: callq .88256 
.68888: movq %rbp, %rsi 
.68891: leaq 0x10(%rax), %rdi 
.68895: movq %rax, %rbx 
.68898: callq .18336 
.68903: testq %r12, %r12 
.68906: je .68944 
.68908: movl 0x10(%r12), %eax 
.68913: movl %eax, (%rbx) 
.68915: movq .148472(%rip), %rax 
.68922: movq %rbx, .148472(%rip) 
.68929: movq %rax, 8(%rbx) 
.68933: jmp .68767 
.68944: movq .148464(%rip), %rax 
.68951: movq %rbx, .148464(%rip) 
.68958: movq %rax, 8(%rbx) 
.68962: movq %r12, %rax 
.68965: popq %rbx 
.68966: popq %rbp 
.68967: popq %r12 
.68969: ret 
