.83877: movq 0x30(%rsp), %rsi 
.83882: addq $0x20, %rsp 
.83886: cmpq %rax, %rsi 
.83889: ja .83992 
.83891: leaq 1(%rax), %rsi 
.83895: leaq .148512(%rip), %rax 
.83902: movq %rsi, (%rbx) 
.83905: cmpq %rax, %r15 
.83908: je .83928 
.83910: movq %r15, %rdi 
.83913: movq %rsi, 0x10(%rsp) 
.83918: callq .18128 
.83923: movq 0x10(%rsp), %rsi 
.83928: movq %rsi, %rdi 
.83931: movq %rsi, 0x10(%rsp) 
.83936: callq .88256 
.83941: subq $8, %rsp 
.83945: movl (%rbp), %r8d 
.83949: movl %r14d, %r9d 
.83952: movq %rax, 8(%rbx) 
.83956: movq %r13, %rcx 
.83959: movq %r12, %rdx 
.83962: movq %rax, %rdi 
.83965: pushq 0x30(%rbp) 
.83968: movq %rax, %r15 
.83971: pushq 0x28(%rbp) 
.83974: pushq 0x30(%rsp) 
.83978: movq 0x30(%rsp), %rsi 
.83983: callq .78960 
.83988: addq $0x20, %rsp 
.83992: movq (%rsp), %rax 
.83996: movl 0xc(%rsp), %ecx 
.84000: movl %ecx, (%rax) 
.84002: addq $0x28, %rsp 
.84006: movq %r15, %rax 
.84009: popq %rbx 
.84010: popq %rbp 
.84011: popq %r12 
.84013: popq %r13 
.84015: popq %r14 
.84017: popq %r15 
.84019: ret 
