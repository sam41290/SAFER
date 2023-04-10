.30400: pushq %rbp 
.30401: pushq %rbx 
.30402: movl %edx, %ebx 
.30404: subq $8, %rsp 
.30408: testq %rdi, %rdi 
.30411: je .30560 
.30417: xorl %esi, %esi 
.30419: movq %rdi, %rbp 
.30422: callq .71376 
.30427: movq .144008(%rip), %rsi 
.30434: movq %rbp, %rdi 
.30437: subl %eax, %ebx 
.30439: movl $0, %eax 
.30444: cmovsl %eax, %ebx 
.30447: callq .19024 
.30452: movq %rbp, %rdi 
.30455: callq .18624 
.30460: movslq %ebx, %rbp 
.30463: addq %rax, %rbp 
.30466: nopw (%rax, %rax) 
.30472: movq .144008(%rip), %rdi 
.30479: movq 0x28(%rdi), %rax 
.30483: cmpq 0x30(%rdi), %rax 
.30487: jae .30544 
.30489: leaq 1(%rax), %rdx 
.30493: movq %rdx, 0x28(%rdi) 
.30497: movb $0x20, (%rax) 
.30500: subl $1, %ebx 
.30503: cmpl $-1, %ebx 
.30506: jne .30472 
.30508: movq .147960(%rip), %rax 
.30515: leaq 1(%rbp, %rax), %rax 
.30520: movq %rax, .147960(%rip) 
.30527: addq $8, %rsp 
.30531: popq %rbx 
.30532: popq %rbp 
.30533: ret 
.30544: movl $0x20, %esi 
.30549: callq .18768 
.30554: jmp .30500 
.30560: movq %rsi, %rcx 
.30563: movl $1, %edi 
.30568: xorl %eax, %eax 
.30570: movslq %ebx, %rbp 
.30573: leaq .104412(%rip), %rsi 
.30580: callq .19472 
.30585: jmp .30508 
.30626: addq $0x10, %rsp 
.30630: movl %r12d, %edx 
.30633: movq %r8, %rdi 
.30636: popq %r12 
.30638: jmp .30400 
.30643: nopl (%rax, %rax) 
.30648: movq %rsi, 8(%rsp) 
.30653: callq .68544 
.30658: movq 8(%rsp), %rsi 
.30663: movq %rax, %r8 
.30666: jmp .30626 
