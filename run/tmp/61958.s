.19744: endbr64 
.19748: bnd jmpq *.143232(%rip) 
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
.61958: nopw %cs:(%rax, %rax) 
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
