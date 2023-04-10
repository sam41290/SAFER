.54228: nopw %cs:(%rax, %rax) 
.54238: nop 
.54240: endbr64 
.54244: pushq %r15 
.54246: movl $0x401, %eax 
.54251: pushq %r14 
.54253: movabsq $0x7ffffffffffffffe, %r14 
.54263: pushq %r13 
.54265: movabsq $0x3fffffffffffffff, %r13 
.54275: pushq %r12 
.54277: movq %rdi, %r12 
.54280: pushq %rbp 
.54281: pushq %rbx 
.54282: leaq 1(%rsi), %rbx 
.54286: subq $8, %rsp 
.54290: cmpq $0x401, %rsi 
.54297: cmovaeq %rax, %rbx 
.54301: nopl (%rax) 
.54304: movq %rbx, %rdi 
.54307: callq .18144 
.54312: movq %rax, %rbp 
.54315: testq %rax, %rax 
.54318: je .54379 
.54320: movq %rbx, %rdx 
.54323: movq %rax, %rsi 
.54326: movq %r12, %rdi 
.54329: callq .18464 
.54334: movq %rax, %r15 
.54337: testq %rax, %rax 
.54340: js .54424 
.54342: cmpq %r15, %rbx 
.54345: ja .54448 
.54347: movq %rbp, %rdi 
.54350: callq .18128 
.54355: cmpq %r13, %rbx 
.54358: ja .54400 
.54360: addq %rbx, %rbx 
.54363: movq %rbx, %rdi 
.54366: callq .18144 
.54371: movq %rax, %rbp 
.54374: testq %rax, %rax 
.54377: jne .54320 
.54379: addq $8, %rsp 
.54383: movq %rbp, %rax 
.54386: popq %rbx 
.54387: popq %rbp 
.54388: popq %r12 
.54390: popq %r13 
.54392: popq %r14 
.54394: popq %r15 
.54396: ret 
.54400: cmpq %r14, %rbx 
.54403: ja .54464 
.54405: movabsq $0x7fffffffffffffff, %rbx 
.54415: jmp .54304 
.54424: callq .18272 
.54429: cmpl $0x22, (%rax) 
.54432: je .54342 
.54434: movq %rbp, %rdi 
.54437: xorl %ebp, %ebp 
.54439: callq .18128 
.54444: jmp .54379 
.54448: movb $0, (%rbp, %r15) 
.54454: jmp .54379 
.54464: callq .18272 
.54469: xorl %ebp, %ebp 
.54471: movl $0xc, (%rax) 
.54477: jmp .54379 
