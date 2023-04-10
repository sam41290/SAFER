.19744: endbr64 
.19748: bnd jmpq *.143232(%rip) 
.61687: nopw (%rax, %rax) 
.61696: endbr64 
.61700: pushq %r13 
.61702: pushq %r12 
.61704: xorl %r12d, %r12d 
.61707: pushq %rbp 
.61708: movq %rsi, %rbp 
.61711: pushq %rbx 
.61712: subq $8, %rsp 
.61716: movq (%rdi), %rcx 
.61719: movq 8(%rdi), %rsi 
.61723: movq 0x20(%rdi), %r8 
.61727: movq 0x10(%rdi), %rbx 
.61731: movq 0x18(%rdi), %r13 
.61735: cmpq %rsi, %rcx 
.61738: jb .61753 
.61740: jmp .61805 
.61744: addq $0x10, %rcx 
.61748: cmpq %rsi, %rcx 
.61751: jae .61805 
.61753: cmpq $0, (%rcx) 
.61757: je .61744 
.61759: movq 8(%rcx), %rax 
.61763: movl $1, %edx 
.61768: testq %rax, %rax 
.61771: je .61789 
.61773: nopl (%rax) 
.61776: movq 8(%rax), %rax 
.61780: addq $1, %rdx 
.61784: testq %rax, %rax 
.61787: jne .61776 
.61789: cmpq %rdx, %r12 
.61792: cmovbq %rdx, %r12 
.61796: addq $0x10, %rcx 
.61800: cmpq %rsi, %rcx 
.61803: jb .61753 
.61805: movq %r8, %rcx 
.61808: leaq .114402(%rip), %rdx 
.61815: movq %rbp, %rdi 
.61818: xorl %eax, %eax 
.61820: movl $1, %esi 
.61825: callq .19744 
.61830: xorl %eax, %eax 
.61832: movq %rbx, %rcx 
.61835: movl $1, %esi 
.61840: leaq .114426(%rip), %rdx 
.61847: movq %rbp, %rdi 
.61850: callq .19744 
.61855: testq %r13, %r13 
.61858: js .61968 
.61860: pxor %xmm0, %xmm0 
.61864: cvtsi2sdq %r13, %xmm0 
.61869: mulsd .114576(%rip), %xmm0 
.61877: testq %rbx, %rbx 
.61880: js .62009 
.61882: pxor %xmm1, %xmm1 
.61886: cvtsi2sdq %rbx, %xmm1 
.61891: divsd %xmm1, %xmm0 
.61895: movq %r13, %rcx 
.61898: movq %rbp, %rdi 
.61901: movl $1, %esi 
.61906: leaq .114480(%rip), %rdx 
.61913: movl $1, %eax 
.61918: callq .19744 
.61923: addq $8, %rsp 
.61927: movq %r12, %rcx 
.61930: movq %rbp, %rdi 
.61933: popq %rbx 
.61934: leaq .114450(%rip), %rdx 
.61941: popq %rbp 
.61942: movl $1, %esi 
.61947: popq %r12 
.61949: xorl %eax, %eax 
.61951: popq %r13 
.61953: jmp .19744 
.61968: movq %r13, %rax 
.61971: movq %r13, %rdx 
.61974: pxor %xmm0, %xmm0 
.61978: shrq $1, %rax 
.61981: andl $1, %edx 
.61984: orq %rdx, %rax 
.61987: cvtsi2sdq %rax, %xmm0 
.61992: addsd %xmm0, %xmm0 
.61996: mulsd .114576(%rip), %xmm0 
.62004: testq %rbx, %rbx 
.62007: jns .61882 
.62009: movq %rbx, %rax 
.62012: andl $1, %ebx 
.62015: pxor %xmm1, %xmm1 
.62019: shrq $1, %rax 
.62022: orq %rbx, %rax 
.62025: cvtsi2sdq %rax, %xmm1 
.62030: addsd %xmm1, %xmm1 
.62034: jmp .61891 
