.62925: nopl (%rax) 
.62928: endbr64 
.62932: pushq %r12 
.62934: pushq %rbp 
.62935: movq %rdi, %rbp 
.62938: pushq %rbx 
.62939: movq (%rdi), %r12 
.62942: cmpq 8(%rdi), %r12 
.62946: jb .62970 
.62948: jmp .63083 
.62960: addq $0x10, %r12 
.62964: cmpq %r12, 8(%rbp) 
.62968: jbe .63083 
.62970: cmpq $0, (%r12) 
.62975: je .62960 
.62977: movq 8(%r12), %rbx 
.62982: movq 0x40(%rbp), %rdx 
.62986: testq %rbx, %rbx 
.62989: jne .63003 
.62991: jmp .63045 
.63000: movq %rax, %rbx 
.63003: testq %rdx, %rdx 
.63006: je .63017 
.63008: movq (%rbx), %rdi 
.63011: callq *%rdx 
.63013: movq 0x40(%rbp), %rdx 
.63017: movq 8(%rbx), %rax 
.63021: movq 0x48(%rbp), %rcx 
.63025: movq $0, (%rbx) 
.63032: movq %rcx, 8(%rbx) 
.63036: movq %rbx, 0x48(%rbp) 
.63040: testq %rax, %rax 
.63043: jne .63000 
.63045: testq %rdx, %rdx 
.63048: je .63056 
.63050: movq (%r12), %rdi 
.63054: callq *%rdx 
.63056: movq $0, (%r12) 
.63064: addq $0x10, %r12 
.63068: movq $0, -8(%r12) 
.63077: cmpq %r12, 8(%rbp) 
.63081: ja .62970 
.63083: popq %rbx 
.63084: movq $0, 0x18(%rbp) 
.63092: movq $0, 0x20(%rbp) 
.63100: popq %rbp 
.63101: popq %r12 
.63103: ret 
