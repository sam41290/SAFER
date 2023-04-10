.19942: hlt 
.90725: nopw %cs:(%rax, %rax) 
.90735: nop 
.90736: endbr64 
.90740: pushq %r13 
.90742: pushq %r12 
.90744: pushq %rbp 
.90745: pushq %rbx 
.90746: movq %r8, %rbx 
.90749: subq $0x18, %rsp 
.90753: movq %fs:0x28, %rax 
.90762: movq %rax, 8(%rsp) 
.90767: xorl %eax, %eax 
.90769: movl .143864(%rip), %ebp 
.90775: cmpl $3, %edi 
.90778: ja .90872 
.90780: cmpl $1, %edi 
.90783: ja .90921 
.90789: jne .90930 
.90795: leaq .118693(%rip), %r9 
.90802: movslq %esi, %rax 
.90805: testl %esi, %esi 
.90807: js .90895 
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
.90921: leaq .118656(%rip), %r9 
.90928: jmp .90802 
.90930: jmp .19942 
