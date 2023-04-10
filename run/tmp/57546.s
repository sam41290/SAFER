.57546: nopw (%rax, %rax) 
.57552: endbr64 
.57556: pushq %rbp 
.57557: movq %rdi, %rbp 
.57560: pushq %rbx 
.57561: subq $8, %rsp 
.57565: callq .57488 
.57570: testq %rax, %rax 
.57573: movq %rax, %rbx 
.57576: sete %al 
.57579: movzbl %al, %eax 
.57582: leaq 1(%rbx, %rax), %rdi 
.57587: callq .18144 
.57592: movq %rax, %r8 
.57595: testq %rax, %rax 
.57598: je .57627 
.57600: movq %rbx, %rdx 
.57603: movq %rbp, %rsi 
.57606: movq %rax, %rdi 
.57609: callq .19168 
.57614: movq %rax, %r8 
.57617: testq %rbx, %rbx 
.57620: je .57640 
.57622: movb $0, (%r8, %rbx) 
.57627: addq $8, %rsp 
.57631: movq %r8, %rax 
.57634: popq %rbx 
.57635: popq %rbp 
.57636: ret 
.57640: movb $0x2e, (%rax) 
.57643: movl $1, %ebx 
.57648: jmp .57622 
