.93045: addq %r12, %r14 
.93048: andb $0xfd, 0x50(%rbx) 
.93052: movq %r12, 0x10(%rbx) 
.93056: movq %r14, 0x18(%rbx) 
.93060: popq %rbx 
.93061: popq %rbp 
.93062: popq %r12 
.93064: popq %r13 
.93066: popq %r14 
.93068: ret 
.93069: nopl (%rax) 
.93072: movq 8(%rbp), %rax 
.93076: movq %rbp, %rsi 
.93079: movq %rbx, %rdi 
.93082: movq %rax, 8(%r13) 
.93086: callq .92624 
.93091: jmp .93045 
