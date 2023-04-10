.70823: nopw (%rax, %rax) 
.70832: endbr64 
.70836: pushq %r15 
.70838: movq %rdi, %r15 
.70841: pushq %r14 
.70843: pushq %r13 
.70845: pushq %r12 
.70847: pushq %rbp 
.70848: leaq (%rdi, %rsi), %rbp 
.70852: pushq %rbx 
.70853: subq $0x38, %rsp 
.70857: movl %edx, 0xc(%rsp) 
.70861: movq %fs:0x28, %rax 
.70870: movq %rax, 0x28(%rsp) 
.70875: xorl %eax, %eax 
.70877: callq .18608 
.70882: cmpq $1, %rax 
.70886: jbe .71216 
.70892: xorl %r12d, %r12d 
.70895: cmpq %rbp, %r15 
.70898: jae .71160 
.70904: leaq 0x20(%rsp), %r13 
.70909: leaq 0x1c(%rsp), %r14 
.70914: nopw (%rax, %rax) 
.70920: movzbl (%r15), %eax 
.70924: cmpb $0x5f, %al 
.70926: jg .71200 
.70932: cmpb $0x40, %al 
.70934: jg .71139 
.70940: cmpb $0x23, %al 
.70942: jg .71128 
.70948: cmpb $0x1f, %al 
.70950: jg .71139 
.70956: movq $0, (%r13) 
.70964: jmp .71014 
.70976: movl $0x7fffffff, %edx 
.70981: subl %r12d, %edx 
.70984: cmpl %eax, %edx 
.70986: jl .71352 
.70992: addl %eax, %r12d 
.70995: movq %r13, %rdi 
.70998: addq %rbx, %r15 
.71001: callq .19776 
.71006: testl %eax, %eax 
.71008: jne .71147 
.71014: movq %rbp, %rdx 
.71017: movq %r13, %rcx 
.71020: movq %r15, %rsi 
.71023: movq %r14, %rdi 
.71026: subq %r15, %rdx 
.71029: callq .92368 
.71034: cmpq $-1, %rax 
.71038: je .71296 
.71044: cmpq $-2, %rax 
.71048: je .71328 
.71054: movl 0x1c(%rsp), %edi 
.71058: testq %rax, %rax 
.71061: movl $1, %ebx 
.71066: cmovneq %rax, %rbx 
.71070: callq .19296 
.71075: testl %eax, %eax 
.71077: jns .70976 
.71079: testb $2, 0xc(%rsp) 
.71084: jne .71312 
.71090: movl 0x1c(%rsp), %edi 
.71094: callq .18400 
.71099: testl %eax, %eax 
.71101: jne .70995 
.71103: cmpl $0x7fffffff, %r12d 
.71110: je .71352 
.71116: addl $1, %r12d 
.71120: jmp .70995 
.71128: subl $0x25, %eax 
.71131: cmpb $0x1a, %al 
.71133: ja .70956 
.71139: addq $1, %r15 
.71143: addl $1, %r12d 
.71147: cmpq %rbp, %r15 
.71150: jb .70920 
.71156: nopl (%rax) 
.71160: movq 0x28(%rsp), %rax 
.71165: xorq %fs:0x28, %rax 
.71174: jne .71363 
.71180: addq $0x38, %rsp 
.71184: movl %r12d, %eax 
.71187: popq %rbx 
.71188: popq %rbp 
.71189: popq %r12 
.71191: popq %r13 
.71193: popq %r14 
.71195: popq %r15 
.71197: ret 
.71200: subl $0x61, %eax 
.71203: cmpb $0x1d, %al 
.71205: jbe .71139 
.71207: jmp .70956 
.71216: xorl %r12d, %r12d 
.71219: cmpq %rbp, %r15 
.71222: jae .71160 
.71224: callq .19840 
.71229: movl 0xc(%rsp), %edx 
.71233: xorl %r12d, %r12d 
.71236: movq (%rax), %rcx 
.71239: andl $2, %edx 
.71242: nopw (%rax, %rax) 
.71248: movzbl (%r15), %eax 
.71252: addq $1, %r15 
.71256: movzwl (%rcx, %rax, 2), %eax 
.71260: testb $0x40, %ah 
.71263: jne .71273 
.71265: testl %edx, %edx 
.71267: jne .71312 
.71269: testb $2, %al 
.71271: jne .71286 
.71273: cmpl $0x7fffffff, %r12d 
.71280: je .71160 
.71282: addl $1, %r12d 
.71286: cmpq %r15, %rbp 
.71289: jne .71248 
.71291: jmp .71160 
.71296: testb $1, 0xc(%rsp) 
.71301: je .71139 
.71307: nopl (%rax, %rax) 
.71312: movl $0xffffffff, %r12d 
.71318: jmp .71160 
.71328: testb $1, 0xc(%rsp) 
.71333: jne .71312 
.71335: addl $1, %r12d 
.71339: movq %rbp, %r15 
.71342: jmp .71147 
.71352: movl $0x7fffffff, %r12d 
.71358: jmp .71160 
.71363: hlt 
