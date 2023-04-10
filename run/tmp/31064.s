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
.31064: nopl (%rax, %rax) 
.31072: endbr64 
.31076: movl 0xa8(%rdi), %eax 
.31082: movq %rsi, %rcx 
.31085: movl 0xa8(%rsi), %esi 
.31091: cmpl $3, %eax 
.31094: sete %dl 
.31097: cmpl $9, %eax 
.31100: sete %al 
.31103: orl %eax, %edx 
.31105: cmpl $3, %esi 
.31108: sete %al 
.31111: cmpl $9, %esi 
.31114: sete %sil 
.31118: orb %sil, %al 
.31121: jne .31144 
.31123: testb %dl, %dl 
.31125: jne .31168 
.31127: movl $1, %r8d 
.31133: testb %al, %al 
.31135: je .31148 
.31137: movl %r8d, %eax 
.31140: ret 
.31144: testb %dl, %dl 
.31146: je .31127 
.31148: movq (%rdi), %rsi 
.31151: movq (%rcx), %rdi 
.31154: jmp .29456 
.31168: movl $0xffffffff, %r8d 
.31174: jmp .31137 
