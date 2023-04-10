.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.51880: nopl (%rax, %rax) 
.51888: endbr64 
.51892: pushq %r13 
.51894: movq %rsi, %r13 
.51897: movl $0x2e, %esi 
.51902: pushq %r12 
.51904: pushq %rbp 
.51905: movq (%rdi), %r12 
.51908: movq %r12, %rdi 
.51911: callq .18784 
.51916: movq (%r13), %r13 
.51920: movl $0x2e, %esi 
.51925: movq %rax, %rbp 
.51928: movq %r13, %rdi 
.51931: callq .18784 
.51936: testq %rax, %rax 
.51939: je .51984 
.51941: movq %rax, %rsi 
.51944: testq %rbp, %rbp 
.51947: leaq .104446(%rip), %rax 
.51954: cmoveq %rax, %rbp 
.51958: movq %rbp, %rdi 
.51961: callq .19072 
.51966: testl %eax, %eax 
.51968: je .51996 
.51970: popq %rbp 
.51971: popq %r12 
.51973: popq %r13 
.51975: ret 
.51984: leaq .104446(%rip), %rsi 
.51991: testq %rbp, %rbp 
.51994: jne .51958 
.51996: popq %rbp 
.51997: movq %r13, %rsi 
.52000: movq %r12, %rdi 
.52003: popq %r12 
.52005: popq %r13 
.52007: jmp .19072 
