.30508: movq .147960(%rip), %rax 
.30515: leaq 1(%rbp, %rax), %rax 
.30520: movq %rax, .147960(%rip) 
.30527: addq $8, %rsp 
.30531: popq %rbx 
.30532: popq %rbp 
.30533: ret 
.30556: nopl (%rax) 
.30560: movq %rsi, %rcx 
.30563: movl $1, %edi 
.30568: xorl %eax, %eax 
.30570: movslq %ebx, %rbp 
.30573: leaq .104412(%rip), %rsi 
.30580: callq .19472 
.30585: jmp .30508 
