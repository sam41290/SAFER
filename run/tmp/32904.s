.32904: nopl (%rax, %rax) 
.32912: pushq %rbp 
.32913: pushq %rbx 
.32914: subq $0x98, %rsp 
.32921: movq %fs:0x28, %rax 
.32930: movq %rax, 0x88(%rsp) 
.32938: xorl %eax, %eax 
.32940: movq %rsp, %rbx 
.32943: jmp .33033 
.32952: movq .144008(%rip), %rdi 
.32959: callq .19760 
.32964: movq %rbx, %rdx 
.32967: leaq .148000(%rip), %rsi 
.32974: xorl %edi, %edi 
.32976: callq .18208 
.32981: movl .147992(%rip), %ebp 
.32987: movl .147988(%rip), %eax 
.32993: testl %eax, %eax 
.32995: je .33072 
.32997: subl $1, %eax 
.33000: movl $0x13, %ebp 
.33005: movl %eax, .147988(%rip) 
.33011: movl %ebp, %edi 
.33013: callq .18240 
.33018: xorl %edx, %edx 
.33020: movq %rbx, %rsi 
.33023: movl $2, %edi 
.33028: callq .18208 
.33033: movl .147992(%rip), %eax 
.33039: testl %eax, %eax 
.33041: jne .33053 
.33043: movl .147988(%rip), %eax 
.33049: testl %eax, %eax 
.33051: je .33088 
.33053: cmpb $0, .148240(%rip) 
.33060: je .32952 
.33062: callq .32864 
.33067: jmp .32952 
.33072: xorl %esi, %esi 
.33074: movl %ebp, %edi 
.33076: callq .19088 
.33081: jmp .33011 
.33088: movq 0x88(%rsp), %rax 
.33096: xorq %fs:0x28, %rax 
.33105: jne .33117 
.33107: addq $0x98, %rsp 
.33114: popq %rbx 
.33115: popq %rbp 
.33116: ret 
.33117: hlt 
