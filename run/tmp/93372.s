.93372: nopl (%rax) 
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
