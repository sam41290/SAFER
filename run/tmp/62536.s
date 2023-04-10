.62536: nopl (%rax, %rax) 
.62544: endbr64 
.62548: movzbl (%rdi), %ecx 
.62551: xorl %edx, %edx 
.62553: testb %cl, %cl 
.62555: je .62589 
.62557: nopl (%rax) 
.62560: movq %rdx, %rax 
.62563: addq $1, %rdi 
.62567: shlq $5, %rax 
.62571: subq %rdx, %rax 
.62574: xorl %edx, %edx 
.62576: addq %rcx, %rax 
.62579: movzbl (%rdi), %ecx 
.62582: divq %rsi 
.62585: testb %cl, %cl 
.62587: jne .62560 
.62589: movq %rdx, %rax 
.62592: ret 
