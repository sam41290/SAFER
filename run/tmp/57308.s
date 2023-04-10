.57308: nopl (%rax) 
.57312: endbr64 
.57316: pushq %r12 
.57318: pushq %rbx 
.57319: subq $8, %rsp 
.57323: movq .144008(%rip), %rdi 
.57330: callq .94832 
.57335: testl %eax, %eax 
.57337: je .57361 
.57339: callq .18272 
.57344: cmpb $0, .148432(%rip) 
.57351: movq %rax, %rbx 
.57354: je .57385 
.57356: cmpl $0x20, (%rax) 
.57359: jne .57385 
.57361: movq .144064(%rip), %rdi 
.57368: callq .94832 
.57373: testl %eax, %eax 
.57375: jne .57448 
.57377: addq $8, %rsp 
.57381: popq %rbx 
.57382: popq %r12 
.57384: ret 
.57385: xorl %edi, %edi 
.57387: movl $5, %edx 
.57392: leaq .114335(%rip), %rsi 
.57399: callq .18592 
.57404: movq .148440(%rip), %rdi 
.57411: movq %rax, %r12 
.57414: testq %rdi, %rdi 
.57417: je .57459 
.57419: callq .85552 
.57424: movl (%rbx), %esi 
.57426: movq %r12, %r8 
.57429: xorl %edi, %edi 
.57431: movq %rax, %rcx 
.57434: leaq .104844(%rip), %rdx 
.57441: xorl %eax, %eax 
.57443: callq .19552 
.57448: movl .143864(%rip), %edi 
.57454: hlt 
.57459: movl (%rbx), %esi 
.57461: movq %rax, %rcx 
.57464: leaq .114332(%rip), %rdx 
.57471: xorl %edi, %edi 
.57473: xorl %eax, %eax 
.57475: callq .19552 
.57480: jmp .57448 
