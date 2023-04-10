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
.42416: endbr64 
.42420: movq 0x48(%rsi), %rax 
.42424: cmpq %rax, 0x48(%rdi) 
.42428: jg .42464 
.42430: jne .42448 
.42432: movq (%rsi), %rsi 
.42435: movq (%rdi), %rdi 
.42438: jmp .29456 
.42443: nopl (%rax, %rax) 
.42448: setl %al 
.42451: movzbl %al, %eax 
.42454: ret 
.42455: nopw (%rax, %rax) 
.42464: movl $0xffffffff, %eax 
.42469: ret 
