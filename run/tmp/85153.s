.19922: hlt 
.85153: nopw %cs:(%rax, %rax) 
.85164: nopl (%rax) 
.85168: endbr64 
.85172: subq $0x48, %rsp 
.85176: movq %fs:0x28, %rax 
.85185: movq %rax, 0x38(%rsp) 
.85190: xorl %eax, %eax 
.85192: cmpl $0xa, %esi 
.85195: je .19922 
.85201: movq %rdx, %r8 
.85204: movl %esi, (%rsp) 
.85207: movq %rcx, %rdx 
.85210: movq %rsp, %rcx 
.85213: movq %r8, %rsi 
.85216: movl $0, 4(%rsp) 
.85224: movq $0, 8(%rsp) 
.85233: movq $0, 0x10(%rsp) 
.85242: movq $0, 0x18(%rsp) 
.85251: movq $0, 0x20(%rsp) 
.85260: movq $0, 0x28(%rsp) 
.85269: movq $0, 0x30(%rsp) 
.85278: callq .83648 
.85283: movq 0x38(%rsp), %rdx 
.85288: xorq %fs:0x28, %rdx 
.85297: jne .85304 
.85299: addq $0x48, %rsp 
.85303: ret 
.85304: hlt 
