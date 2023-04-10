.84472: nopl (%rax, %rax) 
.84480: endbr64 
.84484: pushq %r15 
.84486: leaq .148768(%rip), %rax 
.84493: pushq %r14 
.84495: movq %rsi, %r14 
.84498: pushq %r13 
.84500: movq %rdi, %r13 
.84503: pushq %r12 
.84505: pushq %rbp 
.84506: movq %rdx, %rbp 
.84509: pushq %rbx 
.84510: movq %rcx, %rbx 
.84513: subq $0x28, %rsp 
.84517: testq %rcx, %rcx 
.84520: cmoveq %rax, %rbx 
.84524: callq .18272 
.84529: xorl %r9d, %r9d 
.84532: testq %rbp, %rbp 
.84535: movq %r14, %rcx 
.84538: movq %rax, %r12 
.84541: movl (%rax), %eax 
.84543: sete %r9b 
.84547: leaq 8(%rbx), %r10 
.84551: subq $8, %rsp 
.84555: orl 4(%rbx), %r9d 
.84559: movl (%rbx), %r8d 
.84562: movq %r13, %rdx 
.84565: movl %eax, 0x18(%rsp) 
.84569: xorl %esi, %esi 
.84571: xorl %edi, %edi 
.84573: pushq 0x30(%rbx) 
.84576: pushq 0x28(%rbx) 
.84579: pushq %r10 
.84581: movq %r10, 0x38(%rsp) 
.84586: movl %r9d, 0x34(%rsp) 
.84591: callq .78960 
.84596: addq $0x20, %rsp 
.84600: leaq 1(%rax), %rsi 
.84604: movq %rax, %r15 
.84607: movq %rsi, %rdi 
.84610: movq %rsi, 8(%rsp) 
.84615: callq .88256 
.84620: subq $8, %rsp 
.84624: pushq 0x30(%rbx) 
.84627: movl (%rbx), %r8d 
.84630: pushq 0x28(%rbx) 
.84633: movq %r14, %rcx 
.84636: movq %r13, %rdx 
.84639: movq %rax, %rdi 
.84642: movq 0x30(%rsp), %r10 
.84647: pushq %r10 
.84649: movq 0x28(%rsp), %rsi 
.84654: movl 0x34(%rsp), %r9d 
.84659: movq %rax, 0x28(%rsp) 
.84664: callq .78960 
.84669: movl 0x30(%rsp), %eax 
.84673: addq $0x20, %rsp 
.84677: testq %rbp, %rbp 
.84680: movq 8(%rsp), %r11 
.84685: movl %eax, (%r12) 
.84689: je .84695 
.84691: movq %r15, (%rbp) 
.84695: addq $0x28, %rsp 
.84699: movq %r11, %rax 
.84702: popq %rbx 
.84703: popq %rbp 
.84704: popq %r12 
.84706: popq %r13 
.84708: popq %r14 
.84710: popq %r15 
.84712: ret 
