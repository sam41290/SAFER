.19927: hlt 
.85598: nop 
.85600: endbr64 
.85604: subq $0x48, %rsp 
.85608: movq %fs:0x28, %rax 
.85617: movq %rax, 0x38(%rsp) 
.85622: xorl %eax, %eax 
.85624: cmpl $0xa, %esi 
.85627: je .19927 
.85633: movq %rdx, %r8 
.85636: movl %esi, (%rsp) 
.85639: movq %rsp, %rcx 
.85642: movq $-1, %rdx 
.85649: movabsq $0x400000000000000, %rax 
.85659: movq %r8, %rsi 
.85662: movl $0, 4(%rsp) 
.85670: movq %rax, 8(%rsp) 
.85675: movq $0, 0x10(%rsp) 
.85684: movq $0, 0x18(%rsp) 
.85693: movq $0, 0x20(%rsp) 
.85702: movq $0, 0x28(%rsp) 
.85711: movq $0, 0x30(%rsp) 
.85720: callq .83648 
.85725: movq 0x38(%rsp), %rcx 
.85730: xorq %fs:0x28, %rcx 
.85739: jne .85746 
.85741: addq $0x48, %rsp 
.85745: ret 
.85746: hlt 
