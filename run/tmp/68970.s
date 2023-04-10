.68970: nopw (%rax, %rax) 
.68976: endbr64 
.68980: pushq %r12 
.68982: pushq %rbp 
.68983: movl %edi, %ebp 
.68985: pushq %rbx 
.68986: movq .148456(%rip), %rbx 
.68993: testq %rbx, %rbx 
.68996: jne .69017 
.68998: jmp .69040 
.69008: movq 8(%rbx), %rbx 
.69012: testq %rbx, %rbx 
.69015: je .69040 
.69017: cmpl %ebp, (%rbx) 
.69019: jne .69008 
.69021: xorl %eax, %eax 
.69023: cmpb $0, 0x10(%rbx) 
.69027: je .69033 
.69029: leaq 0x10(%rbx), %rax 
.69033: popq %rbx 
.69034: popq %rbp 
.69035: popq %r12 
.69037: ret 
.69040: movl %ebp, %edi 
.69042: leaq .104446(%rip), %r12 
.69049: callq .18720 
.69054: movl $0x18, %edi 
.69059: testq %rax, %rax 
.69062: je .69083 
.69064: movq (%rax), %r12 
.69067: movq %r12, %rdi 
.69070: callq .18624 
.69075: leaq 0x18(%rax), %rdi 
.69079: andq $0xfffffffffffffff8, %rdi 
.69083: callq .88256 
.69088: movq %r12, %rsi 
.69091: movl %ebp, (%rax) 
.69093: leaq 0x10(%rax), %rdi 
.69097: movq %rax, %rbx 
.69100: callq .18336 
.69105: movq .148456(%rip), %rax 
.69112: movq %rbx, .148456(%rip) 
.69119: movq %rax, 8(%rbx) 
.69123: jmp .69021 
