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
.88325: nopw %cs:(%rax, %rax) 
.88336: endbr64 
.88340: jmp .88256 
