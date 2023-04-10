.84181: nopw %cs:(%rax, %rax) 
.84192: endbr64 
.84196: testq %rdi, %rdi 
.84199: leaq .148768(%rip), %rax 
.84206: movl %esi, %ecx 
.84208: cmoveq %rax, %rdi 
.84212: movl %esi, %eax 
.84214: andl $0x1f, %ecx 
.84217: shrb $5, %al 
.84220: movzbl %al, %eax 
.84223: leaq 8(%rdi, %rax, 4), %rsi 
.84228: movl (%rsi), %edi 
.84230: movl %edi, %eax 
.84232: shrl %cl, %eax 
.84234: xorl %eax, %edx 
.84236: andl $1, %eax 
.84239: andl $1, %edx 
.84242: shll %cl, %edx 
.84244: xorl %edi, %edx 
.84246: movl %edx, (%rsi) 
.84248: ret 
