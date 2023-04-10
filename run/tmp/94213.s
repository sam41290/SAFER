.93376: testq %rdi, %rdi 
.93379: je .93416 
.93381: pushq %rbx 
.93382: movq %rdi, %rbx 
.93385: nopl (%rax) 
.93392: movq %rbx, %rdi 
.93395: movq (%rbx), %rbx 
.93398: callq .18128 
.93403: testq %rbx, %rbx 
.93406: jne .93392 
.93408: popq %rbx 
.93409: ret 
.93416: ret 
.94213: nopw %cs:(%rax, %rax) 
.94224: endbr64 
.94228: cmpq $1, %rdi 
.94232: je .94240 
.94234: jmp .93376 
.94240: ret 
