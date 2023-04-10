.57757: nopl (%rax) 
.57760: endbr64 
.57764: pushq %rbx 
.57765: movq %rdi, %rbx 
.57768: callq .18624 
.57773: cmpq $1, %rax 
.57777: jbe .57790 
.57779: cmpb $0x2f, -1(%rbx, %rax) 
.57784: leaq -1(%rax), %rdx 
.57788: je .57792 
.57790: popq %rbx 
.57791: ret 
.57792: movq %rdx, %rax 
.57795: jmp .57773 
