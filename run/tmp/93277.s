.93277: nopl (%rax) 
.93280: endbr64 
.93284: movq 8(%rdi), %rax 
.93288: xorl %r8d, %r8d 
.93291: testq %rax, %rax 
.93294: je .93314 
.93296: movq (%rax), %rdx 
.93299: subq %rax, %rdx 
.93302: movq 8(%rax), %rax 
.93306: addq %rdx, %r8 
.93309: testq %rax, %rax 
.93312: jne .93296 
.93314: movq %r8, %rax 
.93317: ret 
