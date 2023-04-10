.58134: nopw %cs:(%rax, %rax) 
.58144: endbr64 
.58148: subq $0x28, %rsp 
.58152: movq %fs:0x28, %rax 
.58161: movq %rax, 0x18(%rsp) 
.58166: xorl %eax, %eax 
.58168: testq %rdi, %rdi 
.58171: je .58208 
.58173: movq 8(%rdx), %rax 
.58177: movq %rsi, (%rsp) 
.58181: movq %rsp, %rsi 
.58184: movq %rax, 8(%rsp) 
.58189: movq (%rdx), %rax 
.58192: movq %rax, 0x10(%rsp) 
.58197: callq .62048 
.58202: testq %rax, %rax 
.58205: setne %al 
.58208: movq 0x18(%rsp), %rcx 
.58213: xorq %fs:0x28, %rcx 
.58222: jne .58229 
.58224: addq $0x28, %rsp 
.58228: ret 
.58229: hlt 
