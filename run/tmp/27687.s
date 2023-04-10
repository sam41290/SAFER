.27687: nopw (%rax, %rax) 
.27696: pushq %r15 
.27698: xorl %esi, %esi 
.27700: pushq %r14 
.27702: pushq %r13 
.27704: pushq %r12 
.27706: pushq %rbp 
.27707: pushq %rbx 
.27708: subq $0x658, %rsp 
.27715: movq %fs:0x28, %rax 
.27724: movq %rax, 0x648(%rsp) 
.27732: xorl %eax, %eax 
.27734: leaq 0x30(%rsp), %rdi 
.27739: movq %rdi, 0x18(%rsp) 
.27744: leaq .143424(%rip), %rax 
.27751: movq (%rax, %rsi), %rax 
.27755: movzbl (%rax), %edx 
.27758: testb %dl, %dl 
.27760: je .27787 
.27762: nopw (%rax, %rax) 
.27768: movzbl 1(%rax), %ecx 
.27772: cmpb $0x25, %dl 
.27775: je .27792 
.27777: movl %ecx, %edx 
.27779: addq $1, %rax 
.27783: testb %dl, %dl 
.27785: jne .27768 
.27787: xorl %eax, %eax 
.27789: jmp .27806 
.27792: cmpb $0x25, %cl 
.27795: je .27984 
.27801: cmpb $0x62, %cl 
.27804: jne .27777 
.27806: movq %rax, (%rdi, %rsi) 
.27810: addq $8, %rsi 
.27814: cmpq $0x10, %rsi 
.27818: jne .27744 
.27820: cmpq $0, 0x30(%rsp) 
.27826: movl $0xc, %r13d 
.27832: je .28045 
.27838: leaq 0x40(%rsp), %rax 
.27843: leaq 0x28(%rsp), %r14 
.27848: movq %rax, 8(%rsp) 
.27853: leaq 0x640(%rsp), %rax 
.27861: movq %rax, (%rsp) 
.27865: movq 8(%rsp), %r15 
.27870: movl $0x2000e, %ebp 
.27875: xorl %ebx, %ebx 
.27877: nopl (%rax) 
.27880: movl %ebp, %edi 
.27882: movq %r13, 0x28(%rsp) 
.27887: callq .19328 
.27892: movl $0x25, %esi 
.27897: movq %rax, %rdi 
.27900: movq %rax, %r12 
.27903: callq .18704 
.27908: testq %rax, %rax 
.27911: jne .28004 
.27913: xorl %r9d, %r9d 
.27916: xorl %r8d, %r8d 
.27919: movq %r14, %rcx 
.27922: movl $0x80, %edx 
.27927: movq %r15, %rsi 
.27930: movq %r12, %rdi 
.27933: callq .69664 
.27938: cmpq $0x7f, %rax 
.27942: ja .28004 
.27944: movq 0x28(%rsp), %rax 
.27949: cmpq %rax, %rbx 
.27952: cmovbq %rax, %rbx 
.27956: addl $1, %ebp 
.27959: subq $-0x80, %r15 
.27963: cmpq (%rsp), %r15 
.27967: jne .27880 
.27969: cmpq %rbx, %r13 
.27972: jbe .28059 
.27974: movq %rbx, %r13 
.27977: jmp .27865 
.27984: movzbl 2(%rax), %edx 
.27988: addq $1, %rax 
.27992: jmp .27779 
.27997: movb $1, .144328(%rip) 
.28004: movq 0x648(%rsp), %rax 
.28012: xorq %fs:0x28, %rax 
.28021: jne .28282 
.28027: addq $0x658, %rsp 
.28034: popq %rbx 
.28035: popq %rbp 
.28036: popq %r12 
.28038: popq %r13 
.28040: popq %r14 
.28042: popq %r15 
.28044: ret 
.28045: cmpq $0, 0x38(%rsp) 
.28051: jne .27838 
.28057: jmp .28004 
.28059: movq $0, 0x10(%rsp) 
.28068: leaq .144352(%rip), %r12 
.28075: movq 0x10(%rsp), %rax 
.28080: leaq .143424(%rip), %rbx 
.28087: movq 8(%rsp), %r14 
.28092: movq (%rbx, %rax, 8), %rbp 
.28096: movq 0x18(%rsp), %rbx 
.28101: imulq $0x600, %rax, %rdi 
.28108: movq (%rbx, %rax, 8), %r15 
.28112: leaq (%r12, %rdi), %r13 
.28116: movq %r15, %rbx 
.28119: subq %rbp, %rbx 
.28122: jmp .28217 
.28128: cmpq $0x80, %rbx 
.28135: jg .28004 
.28141: subq $8, %rsp 
.28145: leaq 2(%r15), %rax 
.28149: movl %ebx, %r9d 
.28152: movl $1, %edx 
.28157: pushq %rax 
.28158: leaq .104356(%rip), %r8 
.28165: movl $0x80, %esi 
.28170: movq %r13, %rdi 
.28173: pushq %r14 
.28175: movq $-1, %rcx 
.28182: xorl %eax, %eax 
.28184: pushq %rbp 
.28185: callq .18224 
.28190: addq $0x20, %rsp 
.28194: cmpl $0x7f, %eax 
.28197: ja .28004 
.28203: subq $-0x80, %r13 
.28207: subq $-0x80, %r14 
.28211: cmpq (%rsp), %r14 
.28215: je .28256 
.28217: testq %r15, %r15 
.28220: jne .28128 
.28222: movq %rbp, %rcx 
.28225: leaq .114332(%rip), %rdx 
.28232: movq %r13, %rdi 
.28235: xorl %eax, %eax 
.28237: movl $0x80, %esi 
.28242: callq .18752 
.28247: jmp .28194 
.28256: cmpq $1, 0x10(%rsp) 
.28262: je .27997 
.28268: movq $1, 0x10(%rsp) 
.28277: jmp .28075 
.28282: hlt 
