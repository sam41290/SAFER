.92160: pushq %rbx 
.92161: testl %edi, %edi 
.92163: je .92248 
.92165: movl %edi, %eax 
.92167: cmpl $0xa, %edi 
.92170: je .92176 
.92172: popq %rbx 
.92173: ret 
.92176: movq (%rsi), %r8 
.92179: movq %rsi, %rbx 
.92182: movl $0xa, %ecx 
.92187: leaq .104543(%rip), %rdi 
.92194: movq %r8, %rsi 
.92197: repe cmpsb (%rdi), (%rsi) 
.92199: seta %dl 
.92202: sbbb $0, %dl 
.92205: testb %dl, %dl 
.92207: jne .92172 
.92209: movq %r8, %rdi 
.92212: callq .19664 
.92217: movq $0, (%rbx) 
.92224: callq .18272 
.92229: movl $0x3d, (%rax) 
.92235: movl $0xffffffff, %eax 
.92240: popq %rbx 
.92241: ret 
.92248: callq .18272 
.92253: movl $0x5f, (%rax) 
.92259: movl $0xffffffff, %eax 
.92264: popq %rbx 
.92265: ret 
.92296: nopl (%rax, %rax) 
.92304: endbr64 
.92308: pushq %rbp 
.92309: movq %rsi, %rbp 
.92312: callq .19056 
.92317: movq %rbp, %rsi 
.92320: popq %rbp 
.92321: movl %eax, %edi 
.92323: jmp .92160 
