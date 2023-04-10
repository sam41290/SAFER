.19360: endbr64 
.19364: bnd jmpq *.143040(%rip) 
.29456: pushq %r12 
.29458: movq %rsi, %r12 
.29461: pushq %rbp 
.29462: movq %rdi, %rbp 
.29465: subq $8, %rsp 
.29469: callq .18272 
.29474: movq %r12, %rsi 
.29477: movq %rbp, %rdi 
.29480: movl $0, (%rax) 
.29486: addq $8, %rsp 
.29490: popq %rbp 
.29491: popq %r12 
.29493: jmp .19360 
.51381: nopw %cs:(%rax, %rax) 
.51392: endbr64 
.51396: pushq %r12 
.51398: movq %rsi, %r12 
.51401: movl $0x2e, %esi 
.51406: pushq %rbp 
.51407: pushq %rbx 
.51408: movq %rdi, %rbx 
.51411: movq (%r12), %rdi 
.51415: callq .18784 
.51420: movq (%rbx), %rdi 
.51423: movl $0x2e, %esi 
.51428: movq %rax, %rbp 
.51431: callq .18784 
.51436: movq %rax, %rsi 
.51439: leaq .104446(%rip), %rax 
.51446: testq %rsi, %rsi 
.51449: cmoveq %rax, %rsi 
.51453: testq %rbp, %rbp 
.51456: cmoveq %rax, %rbp 
.51460: movq %rbp, %rdi 
.51463: callq .29456 
.51468: testl %eax, %eax 
.51470: jne .51488 
.51472: movq (%rbx), %rsi 
.51475: movq (%r12), %rdi 
.51479: popq %rbx 
.51480: popq %rbp 
.51481: popq %r12 
.51483: jmp .29456 
.51488: popq %rbx 
.51489: popq %rbp 
.51490: popq %r12 
.51492: ret 
