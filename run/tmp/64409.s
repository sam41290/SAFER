.64409: nopl (%rax) 
.64416: endbr64 
.64420: pushq %rbx 
.64421: movq %rsi, %rbx 
.64424: subq $0x10, %rsp 
.64428: movq %fs:0x28, %rax 
.64437: movq %rax, 8(%rsp) 
.64442: xorl %eax, %eax 
.64444: movq %rsp, %rdx 
.64447: callq .63744 
.64452: cmpl $-1, %eax 
.64455: je .64496 
.64457: testl %eax, %eax 
.64459: movq %rbx, %rax 
.64462: cmoveq (%rsp), %rax 
.64467: movq 8(%rsp), %rcx 
.64472: xorq %fs:0x28, %rcx 
.64481: jne .64500 
.64483: addq $0x10, %rsp 
.64487: popq %rbx 
.64488: ret 
.64496: xorl %eax, %eax 
.64498: jmp .64467 
.64500: hlt 
