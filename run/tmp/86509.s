.86112: pushq %r14 
.86114: movl %edi, %r14d 
.86117: movq %rsi, %rdi 
.86120: pushq %r13 
.86122: movq %rcx, %r13 
.86125: pushq %r12 
.86127: movl %edx, %r12d 
.86130: pushq %rbp 
.86131: subq $0x138, %rsp 
.86138: movq %fs:0x28, %rax 
.86147: movq %rax, 0x128(%rsp) 
.86155: xorl %eax, %eax 
.86157: callq .94944 
.86162: movq %rsp, %rcx 
.86165: movl %r14d, %esi 
.86168: movl $1, %edi 
.86173: movl $0x100, %r8d 
.86179: movq %rax, %rdx 
.86182: movq %rax, %rbp 
.86185: callq .18736 
.86190: testl %eax, %eax 
.86192: jne .86368 
.86198: movq %rbp, %rdi 
.86201: callq .18128 
.86206: movq %r13, %rdi 
.86209: callq .94944 
.86214: leaq 0x90(%rsp), %rcx 
.86222: movl $0x100, %r8d 
.86228: movl %r12d, %esi 
.86231: movq %rax, %rdx 
.86234: movl $1, %edi 
.86239: movq %rax, %rbp 
.86242: callq .18736 
.86247: testl %eax, %eax 
.86249: jne .86336 
.86251: movq 0x98(%rsp), %rax 
.86259: xorl %r12d, %r12d 
.86262: cmpq %rax, 8(%rsp) 
.86267: jne .86285 
.86269: movq 0x90(%rsp), %rax 
.86277: cmpq %rax, (%rsp) 
.86281: sete %r12b 
.86285: movq %rbp, %rdi 
.86288: callq .18128 
.86293: movq 0x128(%rsp), %rax 
.86301: xorq %fs:0x28, %rax 
.86310: jne .86402 
.86312: addq $0x138, %rsp 
.86319: movl %r12d, %eax 
.86322: popq %rbp 
.86323: popq %r12 
.86325: popq %r13 
.86327: popq %r14 
.86329: ret 
.86336: callq .18272 
.86341: movq %rbp, %rcx 
.86344: movl $1, %edi 
.86349: leaq .114332(%rip), %rdx 
.86356: movl (%rax), %esi 
.86358: xorl %eax, %eax 
.86360: callq .19552 
.86365: jmp .86251 
.86368: callq .18272 
.86373: movq %rbp, %rcx 
.86376: movl $1, %edi 
.86381: leaq .114332(%rip), %rdx 
.86388: movl (%rax), %esi 
.86390: xorl %eax, %eax 
.86392: callq .19552 
.86397: jmp .86198 
.86402: hlt 
.86492: addq $0x18, %rsp 
.86496: xorl %eax, %eax 
.86498: popq %rbx 
.86499: popq %rbp 
.86500: popq %r12 
.86502: popq %r13 
.86504: popq %r14 
.86506: popq %r15 
.86508: ret 
.86509: nopl (%rax) 
.86512: movq %r13, %rdx 
.86515: movq %r12, %rsi 
.86518: movq %rbp, %rdi 
.86521: callq .18992 
.86526: testl %eax, %eax 
.86528: jne .86492 
.86530: movl 0xc(%rsp), %edi 
.86534: addq $0x18, %rsp 
.86538: movq %r14, %rcx 
.86541: movl %ebx, %edx 
.86543: movq %r15, %rsi 
.86546: popq %rbx 
.86547: popq %rbp 
.86548: popq %r12 
.86550: popq %r13 
.86552: popq %r14 
.86554: popq %r15 
.86556: jmp .86112 
