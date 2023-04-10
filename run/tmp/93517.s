.93517: nopl (%rax) 
.93520: endbr64 
.93524: pushq %r12 
.93526: pushq %rbp 
.93527: pushq %rbx 
.93528: testq %rdi, %rdi 
.93531: je .93632 
.93533: movq %rdi, %rbp 
.93536: callq .18624 
.93541: movl $0x76, %edi 
.93546: leaq 1(%rax), %rbx 
.93550: cmpq $0x76, %rbx 
.93554: cmovaeq %rbx, %rdi 
.93558: addq $0x11, %rdi 
.93562: andq $0xfffffffffffffff8, %rdi 
.93566: callq .18144 
.93571: movq %rax, %r12 
.93574: testq %rax, %rax 
.93577: je .93619 
.93579: movq $0, (%rax) 
.93586: movl $1, %eax 
.93591: leaq 9(%r12), %rdi 
.93596: movq %rbx, %rdx 
.93599: movw %ax, 8(%r12) 
.93605: movq %rbp, %rsi 
.93608: callq .19168 
.93613: movb $0, 9(%r12, %rbx) 
.93619: movq %r12, %rax 
.93622: popq %rbx 
.93623: popq %rbp 
.93624: popq %r12 
.93626: ret 
.93632: movl $0x80, %edi 
.93637: callq .18144 
.93642: movq %rax, %r12 
.93645: testq %rax, %rax 
.93648: je .93619 
.93650: xorl %edx, %edx 
.93652: movq $0, (%r12) 
.93660: movq %r12, %rax 
.93663: movw %dx, 8(%r12) 
.93669: popq %rbx 
.93670: popq %rbp 
.93671: popq %r12 
.93673: ret 
