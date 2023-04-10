.19312: endbr64 
.19316: bnd jmpq *.143016(%rip) 
.95242: nopw (%rax, %rax) 
.95248: endbr64 
.95252: pushq %rbp 
.95253: movq %rdi, %rbp 
.95256: testq %rdi, %rdi 
.95259: je .95279 
.95261: callq .19392 
.95266: testl %eax, %eax 
.95268: je .95279 
.95270: testl $0x100, (%rbp) 
.95277: jne .95296 
.95279: movq %rbp, %rdi 
.95282: popq %rbp 
.95283: jmp .19312 
.95296: movq %rbp, %rdi 
.95299: movl $1, %edx 
.95304: xorl %esi, %esi 
.95306: callq .95328 
.95311: movq %rbp, %rdi 
.95314: popq %rbp 
.95315: jmp .19312 
