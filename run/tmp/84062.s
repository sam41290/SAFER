.84062: nop 
.84064: endbr64 
.84068: pushq %r12 
.84070: pushq %rbp 
.84071: movq %rdi, %rbp 
.84074: pushq %rbx 
.84075: callq .18272 
.84080: testq %rbp, %rbp 
.84083: movl $0x38, %esi 
.84088: movl (%rax), %r12d 
.84091: movq %rax, %rbx 
.84094: leaq .148768(%rip), %rax 
.84101: cmoveq %rax, %rbp 
.84105: movq %rbp, %rdi 
.84108: callq .88800 
.84113: movl %r12d, (%rbx) 
.84116: popq %rbx 
.84117: popq %rbp 
.84118: popq %r12 
.84120: ret 
