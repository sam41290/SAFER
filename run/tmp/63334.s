.19892: hlt 
.63334: nopw %cs:(%rax, %rax) 
.63344: endbr64 
.63348: pushq %r13 
.63350: pushq %r12 
.63352: pushq %rbp 
.63353: movq %rdi, %rbp 
.63356: movq %rsi, %rdi 
.63359: pushq %rbx 
.63360: subq $0x68, %rsp 
.63364: movq 0x28(%rbp), %r12 
.63368: movq %fs:0x28, %rax 
.63377: movq %rax, 0x58(%rsp) 
.63382: xorl %eax, %eax 
.63384: movzbl 0x10(%r12), %esi 
.63390: movss 8(%r12), %xmm0 
.63397: callq .60800 
.63402: testq %rax, %rax 
.63405: je .63664 
.63411: movq %rax, %rbx 
.63414: cmpq %rax, 0x10(%rbp) 
.63418: je .63648 
.63424: movl $0x10, %esi 
.63429: movq %rax, %rdi 
.63432: callq .19040 
.63437: movq %rax, (%rsp) 
.63441: testq %rax, %rax 
.63444: je .63664 
.63450: movq %rbx, 0x10(%rsp) 
.63455: shlq $4, %rbx 
.63459: movq %rsp, %r13 
.63462: xorl %edx, %edx 
.63464: addq %rax, %rbx 
.63467: movq 0x30(%rbp), %rax 
.63471: movq %rbp, %rsi 
.63474: movq %r13, %rdi 
.63477: movq %r12, 0x28(%rsp) 
.63482: movq %rax, 0x30(%rsp) 
.63487: movq 0x38(%rbp), %rax 
.63491: movq %rbx, 8(%rsp) 
.63496: movq %rax, 0x38(%rsp) 
.63501: movq 0x40(%rbp), %rax 
.63505: movq $0, 0x18(%rsp) 
.63514: movq %rax, 0x40(%rsp) 
.63519: movq 0x48(%rbp), %rax 
.63523: movq $0, 0x20(%rsp) 
.63532: movq %rax, 0x48(%rsp) 
.63537: callq .61104 
.63542: movl %eax, %r12d 
.63545: testb %al, %al 
.63547: jne .63672 
.63549: movq 0x48(%rsp), %rax 
.63554: movl $1, %edx 
.63559: movq %r13, %rsi 
.63562: movq %rbp, %rdi 
.63565: movq %rax, 0x48(%rbp) 
.63569: callq .61104 
.63574: testb %al, %al 
.63576: je .19892 
.63582: xorl %edx, %edx 
.63584: movq %r13, %rsi 
.63587: movq %rbp, %rdi 
.63590: callq .61104 
.63595: testb %al, %al 
.63597: je .19892 
.63603: movq (%rsp), %rdi 
.63607: callq .18128 
.63612: movq 0x58(%rsp), %rax 
.63617: xorq %fs:0x28, %rax 
.63626: jne .63727 
.63628: addq $0x68, %rsp 
.63632: movl %r12d, %eax 
.63635: popq %rbx 
.63636: popq %rbp 
.63637: popq %r12 
.63639: popq %r13 
.63641: ret 
.63648: movl $1, %r12d 
.63654: jmp .63612 
.63664: xorl %r12d, %r12d 
.63667: jmp .63612 
.63672: movq (%rbp), %rdi 
.63676: callq .18128 
.63681: movq (%rsp), %rax 
.63685: movq %rax, (%rbp) 
.63689: movq 8(%rsp), %rax 
.63694: movq %rax, 8(%rbp) 
.63698: movq 0x10(%rsp), %rax 
.63703: movq %rax, 0x10(%rbp) 
.63707: movq 0x18(%rsp), %rax 
.63712: movq %rax, 0x18(%rbp) 
.63716: movq 0x48(%rsp), %rax 
.63721: movq %rax, 0x48(%rbp) 
.63725: jmp .63612 
.63727: hlt 
