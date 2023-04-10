.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.31944: nopl (%rax, %rax) 
.31952: endbr64 
.31956: pushq %r13 
.31958: pushq %r12 
.31960: pushq %rbp 
.31961: pushq %rbx 
.31962: movq %rdi, %rbx 
.31965: subq $8, %rsp 
.31969: movl 0xa8(%rdi), %eax 
.31975: movl 0xa8(%rsi), %ecx 
.31981: cmpl $3, %eax 
.31984: sete %dl 
.31987: cmpl $9, %eax 
.31990: sete %al 
.31993: orl %eax, %edx 
.31995: cmpl $3, %ecx 
.31998: sete %al 
.32001: cmpl $9, %ecx 
.32004: sete %cl 
.32007: orb %cl, %al 
.32009: jne .32048 
.32011: testb %dl, %dl 
.32013: jne .32176 
.32019: movl $1, %r8d 
.32025: testb %al, %al 
.32027: je .32052 
.32029: addq $8, %rsp 
.32033: movl %r8d, %eax 
.32036: popq %rbx 
.32037: popq %rbp 
.32038: popq %r12 
.32040: popq %r13 
.32042: ret 
.32048: testb %dl, %dl 
.32050: je .32019 
.32052: movq (%rsi), %r12 
.32055: movl $0x2e, %esi 
.32060: movq %r12, %rdi 
.32063: callq .18784 
.32068: movq (%rbx), %r13 
.32071: movl $0x2e, %esi 
.32076: movq %rax, %rbp 
.32079: movq %r13, %rdi 
.32082: callq .18784 
.32087: movq %rax, %rsi 
.32090: testq %rax, %rax 
.32093: je .32152 
.32095: testq %rbp, %rbp 
.32098: leaq .104446(%rip), %rax 
.32105: cmoveq %rax, %rbp 
.32109: movq %rbp, %rdi 
.32112: callq .19072 
.32117: movl %eax, %r8d 
.32120: testl %eax, %eax 
.32122: jne .32029 
.32124: addq $8, %rsp 
.32128: movq %r13, %rsi 
.32131: movq %r12, %rdi 
.32134: popq %rbx 
.32135: popq %rbp 
.32136: popq %r12 
.32138: popq %r13 
.32140: jmp .19072 
.32152: leaq .104446(%rip), %rsi 
.32159: testq %rbp, %rbp 
.32162: jne .32109 
.32164: jmp .32124 
.32176: movl $0xffffffff, %r8d 
.32182: jmp .32029 
