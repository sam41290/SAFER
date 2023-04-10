.28287: nop 
.28288: pushq %r13 
.28290: movl %edx, %r13d 
.28293: pushq %r12 
.28295: movq %rsi, %r12 
.28298: pushq %rbp 
.28299: movq %rdi, %rbp 
.28302: movl $0x20, %edi 
.28307: pushq %rbx 
.28308: subq $8, %rsp 
.28312: callq .88256 
.28317: movq %rax, %rbx 
.28320: testq %r12, %r12 
.28323: je .28336 
.28325: movq %r12, %rdi 
.28328: callq .88848 
.28333: movq %rax, %r12 
.28336: movq %r12, 8(%rbx) 
.28340: testq %rbp, %rbp 
.28343: je .28356 
.28345: movq %rbp, %rdi 
.28348: callq .88848 
.28353: movq %rax, %rbp 
.28356: movq .148352(%rip), %rax 
.28363: movq %rbp, (%rbx) 
.28366: movb %r13b, 0x10(%rbx) 
.28370: movq %rax, 0x18(%rbx) 
.28374: movq %rbx, .148352(%rip) 
.28381: addq $8, %rsp 
.28385: popq %rbx 
.28386: popq %rbp 
.28387: popq %r12 
.28389: popq %r13 
.28391: ret 
