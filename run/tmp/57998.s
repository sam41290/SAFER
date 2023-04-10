.18128: endbr64 
.18132: bnd jmpq *.143296(%rip) 
.57998: nop 
.58000: endbr64 
.58004: testq %rdi, %rdi 
.58007: je .58128 
.58009: pushq %r13 
.58011: movq %rsi, %r13 
.58014: pushq %r12 
.58016: movq %rdi, %r12 
.58019: movl $0x18, %edi 
.58024: pushq %rbp 
.58025: pushq %rbx 
.58026: movq %rdx, %rbx 
.58029: subq $8, %rsp 
.58033: callq .88256 
.58038: movq %r13, %rdi 
.58041: movq %rax, %rbp 
.58044: callq .88848 
.58049: movq %rbp, %rsi 
.58052: movq %r12, %rdi 
.58055: movq %rax, (%rbp) 
.58059: movq 8(%rbx), %rax 
.58063: movq %rax, 8(%rbp) 
.58067: movq (%rbx), %rax 
.58070: movq %rax, 0x10(%rbp) 
.58074: callq .64416 
.58079: testq %rax, %rax 
.58082: je .58129 
.58084: cmpq %rax, %rbp 
.58087: je .58112 
.58089: addq $8, %rsp 
.58093: movq %rbp, %rdi 
.58096: popq %rbx 
.58097: popq %rbp 
.58098: popq %r12 
.58100: popq %r13 
.58102: jmp .65216 
.58112: addq $8, %rsp 
.58116: popq %rbx 
.58117: popq %rbp 
.58118: popq %r12 
.58120: popq %r13 
.58122: ret 
.58128: ret 
.58129: hlt 
.65216: endbr64 
.65220: pushq %rbp 
.65221: movq %rdi, %rbp 
.65224: movq (%rdi), %rdi 
.65227: callq .18128 
.65232: movq %rbp, %rdi 
.65235: popq %rbp 
.65236: jmp .18128 
