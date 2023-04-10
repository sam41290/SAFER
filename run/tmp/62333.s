.62333: nopl (%rax) 
.62336: endbr64 
.62340: movq (%rdi), %r9 
.62343: xorl %eax, %eax 
.62345: cmpq %r9, 8(%rdi) 
.62349: jbe .62402 
.62351: cmpq $0, (%r9) 
.62355: jne .62368 
.62357: addq $0x10, %r9 
.62361: cmpq %r9, 8(%rdi) 
.62365: ja .62351 
.62367: ret 
.62368: movq %r9, %rcx 
.62371: jmp .62397 
.62376: movq (%rcx), %r8 
.62379: addq $1, %rax 
.62383: movq %r8, -8(%rsi, %rax, 8) 
.62388: movq 8(%rcx), %rcx 
.62392: testq %rcx, %rcx 
.62395: je .62357 
.62397: cmpq %rax, %rdx 
.62400: ja .62376 
.62402: ret 
