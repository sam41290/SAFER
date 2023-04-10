.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.31610: nopw (%rax, %rax) 
.31616: endbr64 
.31620: movl 0xa8(%rdi), %eax 
.31626: movl 0xa8(%rsi), %ecx 
.31632: cmpl $3, %eax 
.31635: sete %dl 
.31638: cmpl $9, %eax 
.31641: sete %al 
.31644: orl %eax, %edx 
.31646: cmpl $3, %ecx 
.31649: sete %al 
.31652: cmpl $9, %ecx 
.31655: sete %cl 
.31658: orb %cl, %al 
.31660: jne .31680 
.31662: testb %dl, %dl 
.31664: jne .31736 
.31666: movl $1, %r8d 
.31672: testb %al, %al 
.31674: je .31684 
.31676: movl %r8d, %eax 
.31679: ret 
.31680: testb %dl, %dl 
.31682: je .31666 
.31684: movq 0x60(%rsi), %rax 
.31688: cmpq %rax, 0x60(%rdi) 
.31692: jg .31736 
.31694: jl .31720 
.31696: movq 0x68(%rsi), %r8 
.31700: subl 0x68(%rdi), %r8d 
.31704: jne .31676 
.31706: movq (%rsi), %rsi 
.31709: movq (%rdi), %rdi 
.31712: jmp .19072 
.31720: movl $1, %r8d 
.31726: movl %r8d, %eax 
.31729: ret 
.31736: movl $0xffffffff, %r8d 
.31742: jmp .31676 
