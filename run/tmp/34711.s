.34711: movq %r15, %rdi 
.34714: callq .18128 
.34719: movq 8(%rsp), %r8 
.34724: movq %r8, %rdi 
.34727: callq .18128 
.34732: movq 0x10(%rsp), %r9 
.34737: movq 0x18(%rsp), %r10 
.34742: testq %rbx, %rbx 
.34745: je .35186 
.34751: cmpb $0, .148248(%rip) 
.34758: je .34796 
.34760: movq 0x18(%rbx), %rdx 
.34764: movq 0x20(%rbx), %rax 
.34768: subq %rdx, %rax 
.34771: cmpq $7, %rax 
.34775: jbe .35248 
.34781: movq .147960(%rip), %rax 
.34788: movq %rax, (%rdx) 
.34791: addq $8, 0x18(%rbx) 
.34796: movq 0x28(%rsp), %rdi 
.34801: movq .144008(%rip), %rcx 
.34808: movq %r10, %rdx 
.34811: movl $1, %esi 
.34816: addq %r9, %rdi 
.34819: callq .19408 
.34824: movq .147960(%rip), %rax 
.34831: addq %rbp, %rax 
.34834: cmpb $0, .148248(%rip) 
.34841: movq %rax, .147960(%rip) 
.34848: je .34879 
.34850: movq 0x18(%rbx), %rcx 
.34854: movq 0x20(%rbx), %rdx 
.34858: subq %rcx, %rdx 
.34861: cmpq $7, %rdx 
.34865: jbe .35296 
.34871: movq %rax, (%rcx) 
.34874: addq $8, 0x18(%rbx) 
.34879: testq %r14, %r14 
.34882: je .34959 
.34884: movq .144008(%rip), %rcx 
.34891: movl $6, %edx 
.34896: movl $1, %esi 
.34901: leaq .104440(%rip), %rdi 
.34908: callq .19408 
.34913: testb %r12b, %r12b 
.34916: je .34959 
.34918: movq 0x28(%rsp), %rax 
.34923: movq .144008(%rip), %rdi 
.34930: movzbl -1(%rax, %rbp), %edx 
.34935: movq 0x28(%rdi), %rax 
.34939: cmpq 0x30(%rdi), %rax 
.34943: jae .35344 
.34949: leaq 1(%rax), %rcx 
.34953: movq %rcx, 0x28(%rdi) 
.34957: movb %dl, (%rax) 
.34959: movq 0x28(%rsp), %rdi 
.34964: cmpq %r13, %rdi 
.34967: je .34980 
.34969: cmpq (%rsp), %rdi 
.34973: je .34980 
.34975: callq .18128 
.34980: movzbl 0x27(%rsp), %eax 
.34985: addq %rbp, %rax 
.34988: movq 0x2038(%rsp), %rbx 
.34996: xorq %fs:0x28, %rbx 
.35005: jne .35404 
.35011: addq $0x2048, %rsp 
.35018: popq %rbx 
.35019: popq %rbp 
.35020: popq %r12 
.35022: popq %r13 
.35024: popq %r14 
.35026: popq %r15 
.35028: ret 
.35186: movq 0x28(%rsp), %rdi 
.35191: movq .144008(%rip), %rcx 
.35198: movq %r10, %rdx 
.35201: movl $1, %esi 
.35206: addq %r9, %rdi 
.35209: callq .19408 
.35214: addq %rbp, .147960(%rip) 
.35221: jmp .34879 
.35248: movl $8, %esi 
.35253: movq %rbx, %rdi 
.35256: movq %r10, 0x10(%rsp) 
.35261: movq %r9, 8(%rsp) 
.35266: callq .92864 
.35271: movq 0x18(%rbx), %rdx 
.35275: movq 0x10(%rsp), %r10 
.35280: movq 8(%rsp), %r9 
.35285: jmp .34781 
.35296: movl $8, %esi 
.35301: movq %rbx, %rdi 
.35304: callq .92864 
.35309: movq 0x18(%rbx), %rcx 
.35313: movq .147960(%rip), %rax 
.35320: jmp .34871 
.35344: movzbl %dl, %esi 
.35347: callq .18768 
.35352: jmp .34959 
.35404: hlt 
