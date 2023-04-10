.28824: nopl (%rax, %rax) 
.28832: pushq %r14 
.28834: pushq %r13 
.28836: pushq %r12 
.28838: movl %esi, %r12d 
.28841: pushq %rbp 
.28842: pushq %rbx 
.28843: movq %rdi, %rbx 
.28846: callq .18624 
.28851: leaq 1(%rax), %rcx 
.28855: movl $3, %eax 
.28860: mulq %rcx 
.28863: seto %dl 
.28866: testq %rax, %rax 
.28869: js .29042 
.28875: movzbl %dl, %edx 
.28878: testq %rdx, %rdx 
.28881: jne .29042 
.28887: leaq (%rcx, %rcx, 2), %rdi 
.28891: callq .88256 
.28896: movq %rax, %r13 
.28899: movzbl (%rbx), %eax 
.28902: movq %r13, %rbp 
.28905: testb %al, %al 
.28907: je .29009 
.28909: leaq .147424(%rip), %r14 
.28916: jmp .28942 
.28928: movb %al, (%rbp) 
.28931: addq $1, %rbp 
.28935: movzbl (%rbx), %eax 
.28938: testb %al, %al 
.28940: je .29009 
.28942: addq $1, %rbx 
.28946: cmpb $0x2f, %al 
.28948: jne .28955 
.28950: testb %r12b, %r12b 
.28953: jne .29032 
.28955: movzbl %al, %edx 
.28958: movzbl %al, %r8d 
.28962: cmpb $0, (%r14, %rdx) 
.28967: jne .28928 
.28969: movq %rbp, %rdi 
.28972: movl $1, %esi 
.28977: xorl %eax, %eax 
.28979: addq $3, %rbp 
.28983: leaq .104365(%rip), %rcx 
.28990: movq $-1, %rdx 
.28997: callq .19856 
.29002: movzbl (%rbx), %eax 
.29005: testb %al, %al 
.29007: jne .28942 
.29009: movb $0, (%rbp) 
.29013: movq %r13, %rax 
.29016: popq %rbx 
.29017: popq %rbp 
.29018: popq %r12 
.29020: popq %r13 
.29022: popq %r14 
.29024: ret 
.29032: movb $0x2f, (%rbp) 
.29036: addq $1, %rbp 
.29040: jmp .28935 
.29042: hlt 
