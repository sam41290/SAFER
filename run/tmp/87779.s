.87779: nopl (%rax, %rax) 
.87784: movl %eax, %r10d 
.87787: addl $8, %eax 
.87790: addq 0x10(%r11), %r10 
.87794: movl %eax, (%r11) 
.87797: movq (%r10), %rax 
.87800: movq %rax, (%r8, %r9, 8) 
.87804: testq %rax, %rax 
.87807: je .87856 
.87809: addq $1, %r9 
.87813: cmpq $0xa, %r9 
.87817: je .87856 
.87819: movl (%r11), %eax 
.87822: cmpl $0x2f, %eax 
.87825: jbe .87784 
.87827: movq 8(%r11), %r10 
.87831: leaq 8(%r10), %rax 
.87835: movq %rax, 8(%r11) 
.87839: movq (%r10), %rax 
.87842: movq %rax, (%r8, %r9, 8) 
.87846: testq %rax, %rax 
.87849: jne .87809 
.87851: nopl (%rax, %rax) 
.87856: callq .86608 
.87861: movq 0x58(%rsp), %rax 
.87866: xorq %fs:0x28, %rax 
.87875: jne .87882 
.87877: addq $0x68, %rsp 
.87881: ret 
.87882: hlt 
