.19917: hlt 
.85008: endbr64 
.85012: subq $0x48, %rsp 
.85016: movq %fs:0x28, %rax 
.85025: movq %rax, 0x38(%rsp) 
.85030: xorl %eax, %eax 
.85032: cmpl $0xa, %esi 
.85035: je .19917 
.85041: movq %rdx, %r8 
.85044: movl %esi, (%rsp) 
.85047: movq %rsp, %rcx 
.85050: movq $-1, %rdx 
.85057: movq %r8, %rsi 
.85060: movl $0, 4(%rsp) 
.85068: movq $0, 8(%rsp) 
.85077: movq $0, 0x10(%rsp) 
.85086: movq $0, 0x18(%rsp) 
.85095: movq $0, 0x20(%rsp) 
.85104: movq $0, 0x28(%rsp) 
.85113: movq $0, 0x30(%rsp) 
.85122: callq .83648 
.85127: movq 0x38(%rsp), %rcx 
.85132: xorq %fs:0x28, %rcx 
.85141: jne .85148 
.85143: addq $0x48, %rsp 
.85147: ret 
.85148: hlt 
.85309: nopl (%rax) 
.85312: endbr64 
.85316: movq %rsi, %rdx 
.85319: movl %edi, %esi 
.85321: xorl %edi, %edi 
.85323: jmp .85008 
