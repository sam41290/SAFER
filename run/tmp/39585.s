.39585: nopw %cs:(%rax, %rax) 
.39596: nopl (%rax) 
.39600: pushq %rbp 
.39601: pushq %rbx 
.39602: subq $0x1000, %rsp 
.39609: orq $0, (%rsp) 
.39614: subq $0x1000, %rsp 
.39621: orq $0, (%rsp) 
.39626: subq $0x38, %rsp 
.39630: movq %rdi, %rbx 
.39633: leaq 0x20(%rsp), %rbp 
.39638: leaq 0x10(%rsp), %rdi 
.39643: movl %edx, %ecx 
.39645: movq %fs:0x28, %rax 
.39654: movq %rax, 0x2028(%rsp) 
.39662: xorl %eax, %eax 
.39664: movq %rsi, %rdx 
.39667: leaq 0xf(%rsp), %r9 
.39672: leaq 0x18(%rsp), %r8 
.39677: movq %rbx, %rsi 
.39680: movq %rbp, 0x10(%rsp) 
.39685: callq .33248 
.39690: movq 0x10(%rsp), %rdi 
.39695: cmpq %rbp, %rdi 
.39698: je .39710 
.39700: cmpq %rbx, %rdi 
.39703: je .39710 
.39705: callq .18128 
.39710: movzbl 0xf(%rsp), %eax 
.39715: addq 0x18(%rsp), %rax 
.39720: movq 0x2028(%rsp), %rbx 
.39728: xorq %fs:0x28, %rbx 
.39737: jne .39749 
.39739: addq $0x2038, %rsp 
.39746: popq %rbx 
.39747: popq %rbp 
.39748: ret 
.39749: hlt 
