.62644: nopw %cs:(%rax, %rax) 
.62655: nop 
.62656: endbr64 
.62660: pushq %r15 
.62662: leaq .60320(%rip), %rax 
.62669: movq %rsi, %r15 
.62672: pushq %r14 
.62674: movq %r8, %r14 
.62677: pushq %r13 
.62679: movq %rdi, %r13 
.62682: movl $0x50, %edi 
.62687: pushq %r12 
.62689: pushq %rbp 
.62690: movq %rdx, %rbp 
.62693: pushq %rbx 
.62694: movq %rcx, %rbx 
.62697: subq $8, %rsp 
.62701: testq %rdx, %rdx 
.62704: cmoveq %rax, %rbp 
.62708: testq %rcx, %rcx 
.62711: leaq .60352(%rip), %rax 
.62718: cmoveq %rax, %rbx 
.62722: callq .18144 
.62727: movq %rax, %r12 
.62730: testq %rax, %rax 
.62733: je .62884 
.62739: testq %r15, %r15 
.62742: leaq .114528(%rip), %rax 
.62749: leaq 0x28(%r12), %rdi 
.62754: cmoveq %rax, %r15 
.62758: movq %r15, 0x28(%r12) 
.62763: callq .60672 
.62768: testb %al, %al 
.62770: je .62912 
.62776: movzbl 0x10(%r15), %esi 
.62781: movss 8(%r15), %xmm0 
.62787: movq %r13, %rdi 
.62790: callq .60800 
.62795: movq %rax, 0x10(%r12) 
.62800: movq %rax, %r13 
.62803: testq %rax, %rax 
.62806: je .62912 
.62808: movl $0x10, %esi 
.62813: movq %rax, %rdi 
.62816: callq .19040 
.62821: movq %rax, (%r12) 
.62825: testq %rax, %rax 
.62828: je .62912 
.62830: shlq $4, %r13 
.62834: movq %rbp, 0x30(%r12) 
.62839: addq %rax, %r13 
.62842: movq %rbx, 0x38(%r12) 
.62847: movq %r13, 8(%r12) 
.62852: movq $0, 0x18(%r12) 
.62861: movq $0, 0x20(%r12) 
.62870: movq %r14, 0x40(%r12) 
.62875: movq $0, 0x48(%r12) 
.62884: addq $8, %rsp 
.62888: movq %r12, %rax 
.62891: popq %rbx 
.62892: popq %rbp 
.62893: popq %r12 
.62895: popq %r13 
.62897: popq %r14 
.62899: popq %r15 
.62901: ret 
.62912: movq %r12, %rdi 
.62915: xorl %r12d, %r12d 
.62918: callq .18128 
.62923: jmp .62884 
