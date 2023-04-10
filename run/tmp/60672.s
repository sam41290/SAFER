.60672: movq (%rdi), %rax 
.60675: leaq .114528(%rip), %rdx 
.60682: cmpq %rdx, %rax 
.60685: je .60792 
.60687: movss 8(%rax), %xmm0 
.60692: comiss .114548(%rip), %xmm0 
.60699: jbe .60782 
.60701: movss .114552(%rip), %xmm1 
.60709: comiss %xmm0, %xmm1 
.60712: jbe .60782 
.60714: movss 0xc(%rax), %xmm1 
.60719: comiss .114556(%rip), %xmm1 
.60726: jbe .60782 
.60728: movss (%rax), %xmm1 
.60732: comiss .114560(%rip), %xmm1 
.60739: jb .60782 
.60741: addss .114548(%rip), %xmm1 
.60749: movss 4(%rax), %xmm2 
.60754: comiss %xmm1, %xmm2 
.60757: jbe .60782 
.60759: movss .114564(%rip), %xmm3 
.60767: comiss %xmm2, %xmm3 
.60770: jb .60782 
.60772: comiss %xmm1, %xmm0 
.60775: movl $1, %eax 
.60780: ja .60797 
.60782: movq %rdx, (%rdi) 
.60785: xorl %eax, %eax 
.60787: ret 
.60788: nopl (%rax) 
.60792: movl $1, %eax 
.60797: ret 
