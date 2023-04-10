.92656: pushq %r12 
.92658: pushq %rbp 
.92659: pushq %rbx 
.92660: movq %rdi, %rbx 
.92663: testq %rdx, %rdx 
.92666: je .92768 
.92668: movq %rdx, %rbp 
.92671: leaq -1(%rdx), %r12 
.92675: testq %rsi, %rsi 
.92678: movl $0xfe0, %eax 
.92683: movq %r12, 0x30(%rbx) 
.92687: movq %rbx, %rdi 
.92690: cmoveq %rax, %rsi 
.92694: movq %rsi, (%rbx) 
.92697: callq .92592 
.92702: movq %rax, 8(%rbx) 
.92706: testq %rax, %rax 
.92709: je .92781 
.92711: leaq 0x10(%rax, %r12), %rdx 
.92716: negq %rbp 
.92719: andq %rdx, %rbp 
.92722: movq (%rbx), %rdx 
.92725: movq %rbp, 0x10(%rbx) 
.92729: addq %rax, %rdx 
.92732: movq %rbp, 0x18(%rbx) 
.92736: movq %rdx, (%rax) 
.92739: movq %rdx, 0x20(%rbx) 
.92743: movq $0, 8(%rax) 
.92751: movl $1, %eax 
.92756: andb $0xf9, 0x50(%rbx) 
.92760: popq %rbx 
.92761: popq %rbp 
.92762: popq %r12 
.92764: ret 
.92768: movl $0xf, %r12d 
.92774: movl $0x10, %ebp 
.92779: jmp .92675 
.92781: callq *.143968(%rip) 
.92787: nopw %cs:(%rax, %rax) 
.92798: nop 
.92800: endbr64 
.92804: andb $0xfe, 0x50(%rdi) 
.92808: movq %rcx, 0x38(%rdi) 
.92812: movq %r8, 0x40(%rdi) 
.92816: jmp .92656 
.92821: nopw %cs:(%rax, %rax) 
.92832: endbr64 
.92836: orb $1, 0x50(%rdi) 
.92840: movq %rcx, 0x38(%rdi) 
.92844: movq %r8, 0x40(%rdi) 
.92848: movq %r9, 0x48(%rdi) 
.92852: jmp .92656 
