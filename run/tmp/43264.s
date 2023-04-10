.43264: pushq %rbp 
.43265: pushq %rbx 
.43266: movl %edi, %ebx 
.43268: subq $0x28, %rsp 
.43272: movq %fs:0x28, %rax 
.43281: movq %rax, 0x18(%rsp) 
.43286: xorl %eax, %eax 
.43288: cmpb $0, .148269(%rip) 
.43295: je .43416 
.43297: movq %rsp, %rbp 
.43300: movl %ebx, %r8d 
.43303: leaq .104408(%rip), %rcx 
.43310: xorl %eax, %eax 
.43312: movl $0x15, %edx 
.43317: movl $1, %esi 
.43322: movq %rbp, %rdi 
.43325: callq .19856 
.43330: movq %rbp, %rax 
.43333: movl (%rax), %ecx 
.43335: addq $4, %rax 
.43339: leal -0x1010101(%rcx), %edx 
.43345: notl %ecx 
.43347: andl %ecx, %edx 
.43349: andl $0x80808080, %edx 
.43355: je .43333 
.43357: movl %edx, %ecx 
.43359: shrl $0x10, %ecx 
.43362: testl $0x8080, %edx 
.43368: cmovel %ecx, %edx 
.43371: leaq 2(%rax), %rcx 
.43375: cmoveq %rcx, %rax 
.43379: movl %edx, %esi 
.43381: addb %dl, %sil 
.43384: sbbq $3, %rax 
.43388: subl %ebp, %eax 
.43390: movq 0x18(%rsp), %rbx 
.43395: xorq %fs:0x28, %rbx 
.43404: jne .43452 
.43406: addq $0x28, %rsp 
.43410: popq %rbx 
.43411: popq %rbp 
.43412: ret 
.43416: callq .68544 
.43421: movq %rax, %rdi 
.43424: testq %rax, %rax 
.43427: je .43297 
.43433: xorl %esi, %esi 
.43435: callq .71376 
.43440: movl $0, %edx 
.43445: testl %eax, %eax 
.43447: cmovsl %edx, %eax 
.43450: jmp .43390 
.43452: hlt 
