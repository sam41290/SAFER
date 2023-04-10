.88256: endbr64 
.88260: pushq %rbx 
.88261: movq %rdi, %rbx 
.88264: callq .18144 
.88269: testq %rax, %rax 
.88272: jne .88279 
.88274: testq %rbx, %rbx 
.88277: jne .88281 
.88279: popq %rbx 
.88280: ret 
.88281: hlt 
.88286: nop 
.88288: endbr64 
.88292: movq %rdi, %rax 
.88295: mulq %rsi 
.88298: movq %rax, %rdi 
.88301: seto %al 
.88304: testq %rdi, %rdi 
.88307: js .88319 
.88309: movzbl %al, %eax 
.88312: testq %rax, %rax 
.88315: jne .88319 
.88317: jmp .88256 
.88319: pushq %rax 
.88320: hlt 
