.26729: nopl (%rax) 
.26736: endbr64 
.26740: cmpb $0, .144072(%rip) 
.26747: jne .26792 
.26749: pushq %rbp 
.26750: cmpq $0, .143344(%rip) 
.26758: movq %rsp, %rbp 
.26761: je .26775 
.26763: movq .143368(%rip), %rdi 
.26770: callq .18160 
.26775: callq .26624 
.26780: movb $1, .144072(%rip) 
.26787: popq %rbp 
.26788: ret 
.26792: ret 
