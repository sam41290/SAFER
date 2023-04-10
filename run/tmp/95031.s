.95031: nopw (%rax, %rax) 
.95040: endbr64 
.95044: subq $8, %rsp 
.95048: movl $0xe, %edi 
.95053: callq .19328 
.95058: testq %rax, %rax 
.95061: je .95088 
.95063: cmpb $0, (%rax) 
.95066: leaq .119363(%rip), %rdx 
.95073: cmoveq %rdx, %rax 
.95077: addq $8, %rsp 
.95081: ret 
.95088: leaq .119363(%rip), %rax 
.95095: addq $8, %rsp 
.95099: ret 
