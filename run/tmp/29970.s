.29970: nopw %cs:(%rax, %rax) 
.29981: nopl (%rax) 
.29984: cmpq %rsi, %rdi 
.29987: jae .30176 
.29993: pushq %r12 
.29995: movq %rsi, %r12 
.29998: pushq %rbp 
.29999: pushq %rbx 
.30000: movq %rdi, %rbx 
.30003: jmp .30070 
.30008: movq %r12, %rax 
.30011: xorl %edx, %edx 
.30013: divq %rcx 
.30016: xorl %edx, %edx 
.30018: movq %rax, %r9 
.30021: movq %rbp, %rax 
.30024: divq %rcx 
.30027: cmpq %rax, %r9 
.30030: jbe .30101 
.30032: cmpq %r8, %rsi 
.30035: jae .30152 
.30037: leaq 1(%rsi), %rax 
.30041: movq %rax, 0x28(%rdi) 
.30045: movb $9, (%rsi) 
.30048: movq %rbx, %rax 
.30051: xorl %edx, %edx 
.30053: divq %rcx 
.30056: addq %rbx, %rcx 
.30059: movq %rcx, %rbx 
.30062: subq %rdx, %rbx 
.30065: cmpq %r12, %rbx 
.30068: jae .30125 
.30070: movq .144008(%rip), %rdi 
.30077: movq .148160(%rip), %rcx 
.30084: leaq 1(%rbx), %rbp 
.30088: movq 0x28(%rdi), %rsi 
.30092: movq 0x30(%rdi), %r8 
.30096: testq %rcx, %rcx 
.30099: jne .30008 
.30101: cmpq %r8, %rsi 
.30104: jae .30136 
.30106: leaq 1(%rsi), %rax 
.30110: movq %rax, 0x28(%rdi) 
.30114: movb $0x20, (%rsi) 
.30117: movq %rbp, %rbx 
.30120: cmpq %r12, %rbx 
.30123: jb .30070 
.30125: popq %rbx 
.30126: popq %rbp 
.30127: popq %r12 
.30129: ret 
.30136: movl $0x20, %esi 
.30141: callq .18768 
.30146: jmp .30117 
.30152: movl $9, %esi 
.30157: callq .18768 
.30162: movq .148160(%rip), %rcx 
.30169: jmp .30048 
.30176: ret 
