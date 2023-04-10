.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.52012: nopl (%rax) 
.52016: endbr64 
.52020: pushq %r13 
.52022: movq %rdi, %r13 
.52025: pushq %r12 
.52027: pushq %rbp 
.52028: movq (%rsi), %r12 
.52031: movl $0x2e, %esi 
.52036: movq %r12, %rdi 
.52039: callq .18784 
.52044: movq (%r13), %r13 
.52048: movl $0x2e, %esi 
.52053: movq %rax, %rbp 
.52056: movq %r13, %rdi 
.52059: callq .18784 
.52064: testq %rax, %rax 
.52067: je .52112 
.52069: movq %rax, %rsi 
.52072: testq %rbp, %rbp 
.52075: leaq .104446(%rip), %rax 
.52082: cmoveq %rax, %rbp 
.52086: movq %rbp, %rdi 
.52089: callq .19072 
.52094: testl %eax, %eax 
.52096: je .52124 
.52098: popq %rbp 
.52099: popq %r12 
.52101: popq %r13 
.52103: ret 
.52112: leaq .104446(%rip), %rsi 
.52119: testq %rbp, %rbp 
.52122: jne .52086 
.52124: popq %rbp 
.52125: movq %r13, %rsi 
.52128: movq %r12, %rdi 
.52131: popq %r12 
.52133: popq %r13 
.52135: jmp .19072 
