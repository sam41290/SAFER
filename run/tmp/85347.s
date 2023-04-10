.85347: nopw %cs:(%rax, %rax) 
.85358: nop 
.85360: endbr64 
.85364: subq $0x48, %rsp 
.85368: movdqa .148768(%rip), %xmm0 
.85376: movdqa .148784(%rip), %xmm1 
.85384: movl %edx, %ecx 
.85386: movq %fs:0x28, %rax 
.85395: movq %rax, 0x38(%rsp) 
.85400: xorl %eax, %eax 
.85402: movq .148816(%rip), %rax 
.85409: movq %rsi, %r9 
.85412: andl $0x1f, %ecx 
.85415: movdqa .148800(%rip), %xmm2 
.85423: movaps %xmm0, (%rsp) 
.85427: movq %rsp, %r10 
.85430: movq %rax, 0x30(%rsp) 
.85435: movl %edx, %eax 
.85437: shrb $5, %al 
.85440: movaps %xmm1, 0x10(%rsp) 
.85445: movzbl %al, %eax 
.85448: movaps %xmm2, 0x20(%rsp) 
.85453: leaq 8(%rsp, %rax, 4), %rdx 
.85458: movl (%rdx), %esi 
.85460: movl %esi, %eax 
.85462: shrl %cl, %eax 
.85464: notl %eax 
.85466: andl $1, %eax 
.85469: shll %cl, %eax 
.85471: movq %r10, %rcx 
.85474: xorl %esi, %eax 
.85476: movq %rdi, %rsi 
.85479: xorl %edi, %edi 
.85481: movl %eax, (%rdx) 
.85483: movq %r9, %rdx 
.85486: callq .83648 
.85491: movq 0x38(%rsp), %rdi 
.85496: xorq %fs:0x28, %rdi 
.85505: jne .85512 
.85507: addq $0x48, %rsp 
.85511: ret 
.85512: hlt 
