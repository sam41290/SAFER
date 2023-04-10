.65149: nopl (%rax) 
.65152: endbr64 
.65156: movq 8(%rsi), %rdx 
.65160: xorl %eax, %eax 
.65162: cmpq %rdx, 8(%rdi) 
.65166: je .65176 
.65168: ret 
.65176: movq 0x10(%rsi), %rcx 
.65180: cmpq %rcx, 0x10(%rdi) 
.65184: jne .65168 
.65186: subq $8, %rsp 
.65190: movq (%rsi), %rsi 
.65193: movq (%rdi), %rdi 
.65196: callq .19072 
.65201: testl %eax, %eax 
.65203: sete %al 
.65206: addq $8, %rsp 
.65210: ret 
