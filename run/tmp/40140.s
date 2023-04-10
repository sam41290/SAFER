.39841: movslq .148316(%rip), %rax 
.39848: addq $1, %rax 
.39852: addq %rax, %rbx 
.39855: cmpb $0, .148325(%rip) 
.39862: jne .40072 
.39868: movl 0xc4(%rbp), %edx 
.39874: movq .148176(%rip), %rsi 
.39881: movq (%rbp), %rdi 
.39885: callq .39600 
.39890: leaq (%rbx, %rax), %r8 
.39894: movl .148244(%rip), %eax 
.39900: testl %eax, %eax 
.39902: je .39936 
.39904: movl 0xa8(%rbp), %edx 
.39910: movl 0x30(%rbp), %esi 
.39913: movzbl 0xb8(%rbp), %edi 
.39920: callq .31296 
.39925: testb %al, %al 
.39927: setne %al 
.39930: movzbl %al, %eax 
.39933: addq %rax, %r8 
.39936: movq 0x298(%rsp), %rax 
.39944: xorq %fs:0x28, %rax 
.39953: jne .40178 
.39959: addq $0x2a8, %rsp 
.39966: movq %r8, %rax 
.39969: popq %rbx 
.39970: popq %rbp 
.39971: ret 
.39978: cmpb $0, .148268(%rip) 
.39985: je .39855 
.39991: cmpl $4, .148280(%rip) 
.39998: jne .39841 
.40004: cmpb $0, 0xb8(%rbp) 
.40011: movl $2, %eax 
.40016: je .39852 
.40022: movq 0x58(%rbp), %rdi 
.40026: movq .148256(%rip), %r8 
.40033: movq %rsp, %rsi 
.40036: movl $0x200, %ecx 
.40041: movl .148264(%rip), %edx 
.40047: callq .65440 
.40052: movq %rax, %rdi 
.40055: callq .18624 
.40060: addq $1, %rax 
.40064: jmp .39852 
.40072: cmpl $4, .148280(%rip) 
.40079: je .40160 
.40081: movslq .148308(%rip), %rax 
.40088: addq $1, %rax 
.40092: addq %rax, %rbx 
.40095: jmp .39868 
.40140: movq %rax, %rdi 
.40143: callq .18624 
.40148: leaq 1(%rax), %rbx 
.40152: jmp .39978 
.40160: movq 0xb0(%rbp), %rdi 
.40167: callq .18624 
.40172: addq $1, %rax 
.40176: jmp .40092 
.40178: hlt 
