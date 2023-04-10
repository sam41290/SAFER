.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.42600: nopl (%rax, %rax) 
.42608: endbr64 
.42612: movl 0xa8(%rdi), %eax 
.42618: movl 0xa8(%rsi), %ecx 
.42624: cmpl $3, %eax 
.42627: sete %dl 
.42630: cmpl $9, %eax 
.42633: sete %al 
.42636: orl %eax, %edx 
.42638: cmpl $3, %ecx 
.42641: sete %al 
.42644: cmpl $9, %ecx 
.42647: sete %cl 
.42650: orb %cl, %al 
.42652: jne .42672 
.42654: testb %dl, %dl 
.42656: jne .42720 
.42658: movl $1, %r8d 
.42664: testb %al, %al 
.42666: je .42676 
.42668: movl %r8d, %eax 
.42671: ret 
.42672: testb %dl, %dl 
.42674: je .42658 
.42676: movq 0x48(%rsi), %rax 
.42680: cmpq %rax, 0x48(%rdi) 
.42684: jg .42720 
.42686: jne .42704 
.42688: movq (%rsi), %rsi 
.42691: movq (%rdi), %rdi 
.42694: jmp .19072 
.42704: setl %r8b 
.42708: movzbl %r8b, %r8d 
.42712: movl %r8d, %eax 
.42715: ret 
.42720: movl $0xffffffff, %r8d 
.42726: jmp .42668 
