.88352: endbr64 
.88356: pushq %rbx 
.88357: movq %rsi, %rbx 
.88360: testq %rsi, %rsi 
.88363: jne .88370 
.88365: testq %rdi, %rdi 
.88368: jne .88400 
.88370: movq %rbx, %rsi 
.88373: callq .19424 
.88378: testq %rax, %rax 
.88381: jne .88388 
.88383: testq %rbx, %rbx 
.88386: jne .88409 
.88388: popq %rbx 
.88389: ret 
.88400: callq .18128 
.88405: xorl %eax, %eax 
.88407: popq %rbx 
.88408: ret 
.88409: hlt 
.88596: nopw %cs:(%rax, %rax) 
.88607: nop 
.88608: endbr64 
.88612: movq %rsi, %rax 
.88615: movq (%rsi), %rsi 
.88618: testq %rdi, %rdi 
.88621: je .88664 
.88623: movabsq $0x5555555555555553, %rdx 
.88633: cmpq %rdx, %rsi 
.88636: ja .88690 
.88638: movq %rsi, %rdx 
.88641: shrq $1, %rdx 
.88644: leaq 1(%rdx, %rsi), %rsi 
.88649: movq %rsi, (%rax) 
.88652: jmp .88352 
.88664: testq %rsi, %rsi 
.88667: jne .88688 
.88669: movl $0x80, %esi 
.88674: movq %rsi, (%rax) 
.88677: jmp .88352 
.88688: jns .88649 
.88690: pushq %rax 
.88691: hlt 
