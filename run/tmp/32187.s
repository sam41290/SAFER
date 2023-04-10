.32187: nopl (%rax, %rax) 
.32192: pushq %r15 
.32194: pushq %r14 
.32196: pushq %r13 
.32198: pushq %r12 
.32200: pushq %rbp 
.32201: pushq %rbx 
.32202: subq $0xa8, %rsp 
.32209: movq %fs:0x28, %rax 
.32218: movq %rax, 0x98(%rsp) 
.32226: xorl %eax, %eax 
.32228: testb %dil, %dil 
.32231: jne .32352 
.32233: leaq .99876(%rip), %rbx 
.32240: movl $0x14, %ebp 
.32245: leaq .148000(%rip), %r12 
.32252: leaq 0x2c(%rbx), %r13 
.32256: jmp .32275 
.32264: cmpq %r13, %rbx 
.32267: je .32303 
.32269: movl (%rbx), %ebp 
.32271: addq $4, %rbx 
.32275: movl %ebp, %esi 
.32277: movq %r12, %rdi 
.32280: callq .19696 
.32285: testl %eax, %eax 
.32287: je .32264 
.32289: xorl %esi, %esi 
.32291: movl %ebp, %edi 
.32293: callq .19088 
.32298: cmpq %r13, %rbx 
.32301: jne .32269 
.32303: movq 0x98(%rsp), %rax 
.32311: xorq %fs:0x28, %rax 
.32320: jne .32649 
.32326: addq $0xa8, %rsp 
.32333: popq %rbx 
.32334: popq %rbp 
.32335: popq %r12 
.32337: popq %r13 
.32339: popq %r14 
.32341: popq %r15 
.32343: ret 
.32352: leaq .99876(%rip), %rbp 
.32359: leaq .148000(%rip), %rdi 
.32366: movl $0x14, %r12d 
.32372: movq %rsp, %r13 
.32375: callq .19152 
.32380: leaq 0x2c(%rbp), %r14 
.32384: movq %rbp, %rbx 
.32387: leaq .148000(%rip), %r15 
.32394: jmp .32407 
.32400: movl (%rbx), %r12d 
.32403: addq $4, %rbx 
.32407: xorl %esi, %esi 
.32409: movq %r13, %rdx 
.32412: movl %r12d, %edi 
.32415: callq .18384 
.32420: cmpq $1, (%rsp) 
.32425: je .32438 
.32427: movl %r12d, %esi 
.32430: movq %r15, %rdi 
.32433: callq .19808 
.32438: cmpq %r14, %rbx 
.32441: jne .32400 
.32443: movdqa .148000(%rip), %xmm0 
.32451: movdqa .148016(%rip), %xmm1 
.32459: movl $0x10000000, 0x88(%rsp) 
.32470: movl $0x14, %r12d 
.32476: movdqa .148032(%rip), %xmm2 
.32484: movdqa .148048(%rip), %xmm3 
.32492: leaq .30672(%rip), %r15 
.32499: leaq .26864(%rip), %r14 
.32506: movdqa .148064(%rip), %xmm4 
.32514: movdqa .148080(%rip), %xmm5 
.32522: movups %xmm0, 8(%rsp) 
.32527: movdqa .148096(%rip), %xmm6 
.32535: movdqa .148112(%rip), %xmm7 
.32543: movups %xmm1, 0x18(%rsp) 
.32548: movups %xmm2, 0x28(%rsp) 
.32553: movups %xmm3, 0x38(%rsp) 
.32558: movups %xmm4, 0x48(%rsp) 
.32563: movups %xmm5, 0x58(%rsp) 
.32568: movups %xmm6, 0x68(%rsp) 
.32573: movups %xmm7, 0x78(%rsp) 
.32578: jmp .32592 
.32584: movl (%rbp), %r12d 
.32588: addq $4, %rbp 
.32592: movl %r12d, %esi 
.32595: leaq .148000(%rip), %rdi 
.32602: callq .19696 
.32607: testl %eax, %eax 
.32609: je .32639 
.32611: cmpl $0x14, %r12d 
.32615: movq %r14, %rax 
.32618: movq %r13, %rsi 
.32621: movl %r12d, %edi 
.32624: cmoveq %r15, %rax 
.32628: xorl %edx, %edx 
.32630: movq %rax, (%rsp) 
.32634: callq .18384 
.32639: cmpq %rbx, %rbp 
.32642: jne .32584 
.32644: jmp .32303 
.32649: hlt 
