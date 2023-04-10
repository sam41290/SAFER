.78454: nopw %cs:(%rax, %rax) 
.78464: endbr64 
.78468: subq $0x18, %rsp 
.78472: movq %fs:0x28, %rax 
.78481: movq %rax, 8(%rsp) 
.78486: xorl %eax, %eax 
.78488: movb $0, 7(%rsp) 
.78493: pushq %r9 
.78495: pushq %r8 
.78497: xorl %r8d, %r8d 
.78500: leaq 0x17(%rsp), %r9 
.78505: callq .72176 
.78510: popq %rdx 
.78511: popq %rcx 
.78512: movq 8(%rsp), %rdx 
.78517: xorq %fs:0x28, %rdx 
.78526: jne .78533 
.78528: addq $0x18, %rsp 
.78532: ret 
.78533: hlt 
