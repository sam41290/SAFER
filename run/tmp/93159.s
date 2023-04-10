.19947: hlt 
.93159: nopw (%rax, %rax) 
.93168: endbr64 
.93172: pushq %r12 
.93174: movq %rsi, %r12 
.93177: pushq %rbp 
.93178: pushq %rbx 
.93179: movq 8(%rdi), %rsi 
.93183: movq %rdi, %rbx 
.93186: testq %rsi, %rsi 
.93189: jne .93203 
.93191: jmp .93237 
.93200: movq %rbp, %rsi 
.93203: cmpq %r12, %rsi 
.93206: jae .93216 
.93208: movq (%rsi), %rax 
.93211: cmpq %r12, %rax 
.93214: jae .93256 
.93216: movq 8(%rsi), %rbp 
.93220: movq %rbx, %rdi 
.93223: callq .92624 
.93228: orb $2, 0x50(%rbx) 
.93232: testq %rbp, %rbp 
.93235: jne .93200 
.93237: testq %r12, %r12 
.93240: jne .19947 
.93246: popq %rbx 
.93247: popq %rbp 
.93248: popq %r12 
.93250: ret 
.93256: movq %r12, 0x18(%rbx) 
.93260: movq %r12, 0x10(%rbx) 
.93264: movq %rax, 0x20(%rbx) 
.93268: movq %rsi, 8(%rbx) 
.93272: popq %rbx 
.93273: popq %rbp 
.93274: popq %r12 
.93276: ret 
