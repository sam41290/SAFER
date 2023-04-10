.19942: hlt 
.90809: shlq $5, %rax 
.90813: leaq .118749(%rip), %r12 
.90820: movq (%rcx, %rax), %r13 
.90824: movq %r9, %rsi 
.90827: movl $5, %edx 
.90832: xorl %edi, %edi 
.90834: callq .18592 
.90839: movq %rbx, %r9 
.90842: movq %r13, %r8 
.90845: movq %r12, %rcx 
.90848: movq %rax, %rdx 
.90851: xorl %esi, %esi 
.90853: movl %ebp, %edi 
.90855: xorl %eax, %eax 
.90857: callq .19552 
.90862: hlt 
.90867: nopl (%rax, %rax) 
.90872: cmpl $4, %edi 
.90875: jne .19942 
.90881: leaq .118722(%rip), %r9 
.90888: movslq %esi, %rax 
.90891: testl %esi, %esi 
.90893: jns .90809 
.90895: leaq .118749(%rip), %r12 
.90902: movb %dl, 6(%rsp) 
.90906: leaq 6(%rsp), %r13 
.90911: movb $0, 7(%rsp) 
.90916: subq %rax, %r12 
.90919: jmp .90824 
