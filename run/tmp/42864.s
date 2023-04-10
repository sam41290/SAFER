.19360: endbr64 
.19364: bnd jmpq *.143040(%rip) 
.29456: pushq %r12 
.29458: movq %rsi, %r12 
.29461: pushq %rbp 
.29462: movq %rdi, %rbp 
.29465: subq $8, %rsp 
.29469: callq .18272 
.29474: movq %r12, %rsi 
.29477: movq %rbp, %rdi 
.29480: movl $0, (%rax) 
.29486: addq $8, %rsp 
.29490: popq %rbp 
.29491: popq %r12 
.29493: jmp .19360 
.42864: endbr64 
.42868: movq 0x48(%rdi), %rdx 
.42872: movq %rsi, %rax 
.42875: cmpq %rdx, 0x48(%rsi) 
.42879: jg .42912 
.42881: jne .42896 
.42883: movq (%rdi), %rsi 
.42886: movq (%rax), %rdi 
.42889: jmp .29456 
.42894: nop 
.42896: setl %al 
.42899: movzbl %al, %eax 
.42902: ret 
.42903: nopw (%rax, %rax) 
.42912: movl $0xffffffff, %eax 
.42917: ret 
