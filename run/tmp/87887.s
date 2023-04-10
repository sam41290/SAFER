.87887: nop 
.87888: endbr64 
.87892: pushq %rbx 
.87893: movl $0x20, %r10d 
.87899: subq $0xb0, %rsp 
.87906: movq %r8, 0xa0(%rsp) 
.87914: leaq 0xc0(%rsp), %r11 
.87922: leaq 0x20(%rsp), %r8 
.87927: movq %r9, 0xa8(%rsp) 
.87935: xorl %r9d, %r9d 
.87938: movq %fs:0x28, %rax 
.87947: movq %rax, 0x78(%rsp) 
.87952: xorl %eax, %eax 
.87954: leaq 0xc0(%rsp), %rax 
.87962: movl $0x20, 8(%rsp) 
.87970: movq %rax, 0x10(%rsp) 
.87975: leaq 0x80(%rsp), %rax 
.87983: movq %rax, 0x18(%rsp) 
.87988: movq %rax, %rbx 
.87991: jmp .88032 
.88000: movl %r10d, %eax 
.88003: addl $8, %r10d 
.88007: addq %rbx, %rax 
.88010: movq (%rax), %rax 
.88013: movq %rax, (%r8, %r9, 8) 
.88017: testq %rax, %rax 
.88020: je .88064 
.88022: addq $1, %r9 
.88026: cmpq $0xa, %r9 
.88030: je .88064 
.88032: cmpl $0x2f, %r10d 
.88036: jbe .88000 
.88038: movq %r11, %rax 
.88041: addq $8, %r11 
.88045: movq (%rax), %rax 
.88048: movq %rax, (%r8, %r9, 8) 
.88052: testq %rax, %rax 
.88055: jne .88022 
.88057: nopl (%rax) 
.88064: callq .86608 
.88069: movq 0x78(%rsp), %rax 
.88074: xorq %fs:0x28, %rax 
.88083: jne .88094 
.88085: addq $0xb0, %rsp 
.88092: popq %rbx 
.88093: ret 
.88094: hlt 
