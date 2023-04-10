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
.51272: nopl (%rax, %rax) 
.51280: endbr64 
.51284: pushq %r12 
.51286: movq %rdi, %r12 
.51289: pushq %rbp 
.51290: pushq %rbx 
.51291: movq (%rdi), %rdi 
.51294: movq %rsi, %rbx 
.51297: movl $0x2e, %esi 
.51302: callq .18784 
.51307: movq (%rbx), %rdi 
.51310: movl $0x2e, %esi 
.51315: movq %rax, %rbp 
.51318: callq .18784 
.51323: movq %rax, %rsi 
.51326: leaq .104446(%rip), %rax 
.51333: testq %rsi, %rsi 
.51336: cmoveq %rax, %rsi 
.51340: testq %rbp, %rbp 
.51343: cmoveq %rax, %rbp 
.51347: movq %rbp, %rdi 
.51350: callq .29456 
.51355: testl %eax, %eax 
.51357: jne .51376 
.51359: movq (%rbx), %rsi 
.51362: movq (%r12), %rdi 
.51366: popq %rbx 
.51367: popq %rbp 
.51368: popq %r12 
.51370: jmp .29456 
.51376: popq %rbx 
.51377: popq %rbp 
.51378: popq %r12 
.51380: ret 
