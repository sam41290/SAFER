.62220: nopl (%rax) 
.62224: endbr64 
.62228: pushq %rbp 
.62229: movq %rdi, %rbp 
.62232: pushq %rbx 
.62233: movq %rsi, %rbx 
.62236: subq $8, %rsp 
.62240: callq .60368 
.62245: movq %rax, %rdx 
.62248: jmp .62261 
.62256: testq %rdx, %rdx 
.62259: je .62278 
.62261: movq (%rdx), %rcx 
.62264: movq 8(%rdx), %rdx 
.62268: cmpq %rbx, %rcx 
.62271: jne .62256 
.62273: testq %rdx, %rdx 
.62276: jne .62320 
.62278: movq 8(%rbp), %rdx 
.62282: jmp .62296 
.62288: movq (%rax), %r8 
.62291: testq %r8, %r8 
.62294: jne .62308 
.62296: addq $0x10, %rax 
.62300: cmpq %rax, %rdx 
.62303: ja .62288 
.62305: xorl %r8d, %r8d 
.62308: addq $8, %rsp 
.62312: movq %r8, %rax 
.62315: popq %rbx 
.62316: popq %rbp 
.62317: ret 
.62320: movq (%rdx), %r8 
.62323: addq $8, %rsp 
.62327: popq %rbx 
.62328: popq %rbp 
.62329: movq %r8, %rax 
.62332: ret 
