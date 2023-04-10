.33236: nopw %cs:(%rax, %rax) 
.33247: nop 
.33248: pushq %r15 
.33250: pushq %r14 
.33252: pushq %r13 
.33254: movq %rdx, %r13 
.33257: pushq %r12 
.33259: movl %ecx, %r12d 
.33262: pushq %rbp 
.33263: movq %rsi, %rbp 
.33266: pushq %rbx 
.33267: subq $0x68, %rsp 
.33271: movq %rdi, 0x30(%rsp) 
.33276: movq %r8, 0x20(%rsp) 
.33281: movq %r9, 0x38(%rsp) 
.33286: movq %fs:0x28, %rax 
.33295: movq %rax, 0x58(%rsp) 
.33300: xorl %eax, %eax 
.33302: movq (%rdi), %rax 
.33305: movq %rdx, %rdi 
.33308: movq %rax, 0x18(%rsp) 
.33313: callq .84128 
.33318: cmpl $2, %eax 
.33321: setbe %al 
.33324: andb .148184(%rip), %al 
.33330: movb %al, 0x2f(%rsp) 
.33334: jne .33616 
.33340: xorl %r15d, %r15d 
.33343: testl %r12d, %r12d 
.33346: je .33440 
.33348: movq 0x18(%rsp), %rdi 
.33353: movq %r13, %r8 
.33356: movq %rbp, %rdx 
.33359: movl $0x2000, %esi 
.33364: movq $-1, %rcx 
.33371: callq .84352 
.33376: movq %rax, %r12 
.33379: cmpq $0x1fff, %rax 
.33385: ja .34290 
.33391: movq 0x18(%rsp), %rax 
.33396: movb $1, 0x2f(%rsp) 
.33401: movzbl (%rax), %eax 
.33404: cmpb %al, (%rbp) 
.33407: jne .33425 
.33409: movq %rbp, %rdi 
.33412: callq .18624 
.33417: cmpq %rax, %r12 
.33420: setne 0x2f(%rsp) 
.33425: testl %r15d, %r15d 
.33428: je .33456 
.33430: movq %r12, %rbx 
.33433: jmp .33673 
.33440: movq %rbp, %rdi 
.33443: callq .18624 
.33448: movq %rbp, 0x18(%rsp) 
.33453: movq %rax, %r12 
.33456: cmpq $0, 0x20(%rsp) 
.33462: je .33584 
.33464: callq .18608 
.33469: cmpq $1, %rax 
.33473: ja .34192 
.33479: movq 0x18(%rsp), %rbx 
.33484: leaq (%rbx, %r12), %rbp 
.33488: cmpq %rbx, %rbp 
.33491: jbe .34336 
.33497: callq .19840 
.33502: movq (%rax), %rcx 
.33505: movq %rbx, %rax 
.33508: xorl %ebx, %ebx 
.33510: nopw %cs:(%rax, %rax) 
.33520: movzbl (%rax), %edx 
.33523: movzwl (%rcx, %rdx, 2), %edx 
.33527: andw $0x4000, %dx 
.33532: cmpw $1, %dx 
.33536: sbbq $-1, %rbx 
.33540: addq $1, %rax 
.33544: cmpq %rax, %rbp 
.33547: jne .33520 
.33549: cmpb $0, .148392(%rip) 
.33556: jne .33767 
.33562: movq 0x38(%rsp), %rax 
.33567: movb $0, (%rax) 
.33570: jmp .33796 
.33584: cmpb $0, .148392(%rip) 
.33591: jne .33767 
.33597: movq 0x38(%rsp), %rax 
.33602: movb $0, (%rax) 
.33605: jmp .33804 
.33616: testl %r12d, %r12d 
.33619: jne .34353 
.33625: movq %rbp, %rdi 
.33628: callq .18624 
.33633: movq %rax, %rbx 
.33636: leaq 1(%rax), %r12 
.33640: cmpq $0x1fff, %rax 
.33646: ja .34272 
.33652: movq 0x18(%rsp), %rdi 
.33657: movq %r12, %rdx 
.33660: movq %rbp, %rsi 
.33663: callq .19168 
.33668: movb $0, 0x2f(%rsp) 
.33673: callq .18608 
.33678: movq 0x18(%rsp), %rsi 
.33683: leaq (%rsi, %rbx), %rdi 
.33687: movq %rdi, 0x10(%rsp) 
.33692: cmpq $1, %rax 
.33696: ja .33856 
.33702: movq 0x10(%rsp), %r15 
.33707: movq 0x18(%rsp), %r14 
.33712: cmpq %r14, %r15 
.33715: jbe .33753 
.33717: callq .19840 
.33722: movq %r14, %rdx 
.33725: movq %r15, %rdi 
.33728: movzbl (%rdx), %esi 
.33731: movq (%rax), %rcx 
.33734: testb $0x40, 1(%rcx, %rsi, 2) 
.33739: jne .33744 
.33741: movb $0x3f, (%rdx) 
.33744: addq $1, %rdx 
.33748: cmpq %rdi, %rdx 
.33751: jne .33728 
.33753: movq %rbx, %r12 
.33756: movzbl .148392(%rip), %eax 
.33763: testb %al, %al 
.33765: je .33781 
.33767: movzbl 0x2f(%rsp), %eax 
.33772: xorl $1, %eax 
.33775: andb .148393(%rip), %al 
.33781: movq 0x38(%rsp), %rsi 
.33786: cmpq $0, 0x20(%rsp) 
.33792: movb %al, (%rsi) 
.33794: je .33804 
.33796: movq 0x20(%rsp), %rax 
.33801: movq %rbx, (%rax) 
.33804: movq 0x30(%rsp), %rax 
.33809: movq 0x18(%rsp), %rsi 
.33814: movq %rsi, (%rax) 
.33817: movq 0x58(%rsp), %rax 
.33822: xorq %fs:0x28, %rax 
.33831: jne .34364 
.33837: addq $0x68, %rsp 
.33841: movq %r12, %rax 
.33844: popq %rbx 
.33845: popq %rbp 
.33846: popq %r12 
.33848: popq %r13 
.33850: popq %r14 
.33852: popq %r15 
.33854: ret 
.33856: cmpq %rsi, %rdi 
.33859: jbe .34343 
.33865: movq %rsi, %r12 
.33868: xorl %ebx, %ebx 
.33870: leaq 0x50(%rsp), %rbp 
.33875: movq %rsi, %r13 
.33878: leaq 0x4c(%rsp), %r15 
.33883: nopl (%rax, %rax) 
.33888: movzbl (%r13), %eax 
.33893: cmpb $0x5f, %al 
.33895: jg .34176 
.33901: cmpb $0x40, %al 
.33903: jg .34124 
.33909: cmpb $0x23, %al 
.33911: jg .34112 
.33917: cmpb $0x1f, %al 
.33919: jg .34124 
.33925: movq $0, 0x50(%rsp) 
.33934: movq %r13, %r14 
.33937: jmp .33973 
.33944: movb $0x3f, (%r12) 
.33949: movq %rbp, %rdi 
.33952: addq %r13, %r14 
.33955: addq $1, %rbx 
.33959: movq 8(%rsp), %r12 
.33964: callq .19776 
.33969: testl %eax, %eax 
.33971: jne .34097 
.33973: movq 0x10(%rsp), %rdx 
.33978: movq %r14, %rsi 
.33981: movq %rbp, %rcx 
.33984: movq %r15, %rdi 
.33987: subq %r14, %rdx 
.33990: callq .92368 
.33995: leaq 1(%r12), %rsi 
.34000: movq %rsi, 8(%rsp) 
.34005: cmpq $-1, %rax 
.34009: je .34224 
.34015: cmpq $-2, %rax 
.34019: je .34256 
.34025: movl 0x4c(%rsp), %edi 
.34029: testq %rax, %rax 
.34032: movl $1, %r13d 
.34038: cmovneq %rax, %r13 
.34042: callq .19296 
.34047: testl %eax, %eax 
.34049: js .33944 
.34051: xorl %edx, %edx 
.34053: nopl (%rax) 
.34056: movzbl (%r14, %rdx), %ecx 
.34061: movb %cl, (%r12, %rdx) 
.34065: addq $1, %rdx 
.34069: cmpq %rdx, %r13 
.34072: jne .34056 
.34074: cltq 
.34076: movq %rbp, %rdi 
.34079: addq %r13, %r14 
.34082: addq %r13, %r12 
.34085: addq %rax, %rbx 
.34088: callq .19776 
.34093: testl %eax, %eax 
.34095: je .33973 
.34097: movq %r14, %r13 
.34100: jmp .34140 
.34112: leal -0x25(%rax), %edx 
.34115: cmpb $0x1a, %dl 
.34118: ja .33925 
.34124: movb %al, (%r12) 
.34128: addq $1, %r13 
.34132: addq $1, %rbx 
.34136: addq $1, %r12 
.34140: cmpq %r13, 0x10(%rsp) 
.34145: ja .33888 
.34151: movq %r12, %r14 
.34154: subq 0x18(%rsp), %r14 
.34159: movq %r14, %r12 
.34162: jmp .33756 
.34176: leal -0x61(%rax), %edx 
.34179: cmpb $0x1d, %dl 
.34182: jbe .34124 
.34184: jmp .33925 
.34192: movq 0x18(%rsp), %rdi 
.34197: xorl %edx, %edx 
.34199: movq %r12, %rsi 
.34202: callq .70832 
.34207: movslq %eax, %rbx 
.34210: jmp .33549 
.34224: movb $0x3f, (%r12) 
.34229: movq %r14, %r13 
.34232: addq $1, %rbx 
.34236: addq $1, %r13 
.34240: movq 8(%rsp), %r12 
.34245: jmp .34140 
.34256: movb $0x3f, (%r12) 
.34261: movq 0x10(%rsp), %r13 
.34266: addq $1, %rbx 
.34270: jmp .34240 
.34272: movq %r12, %rdi 
.34275: callq .88256 
.34280: movq %rax, 0x18(%rsp) 
.34285: jmp .33652 
.34290: leaq 1(%rax), %r14 
.34294: movq %r14, %rdi 
.34297: callq .88256 
.34302: movq %r13, %r8 
.34305: movq %rbp, %rdx 
.34308: movq %r14, %rsi 
.34311: movq $-1, %rcx 
.34318: movq %rax, %rdi 
.34321: movq %rax, 0x18(%rsp) 
.34326: callq .84352 
.34331: jmp .33391 
.34336: xorl %ebx, %ebx 
.34338: jmp .33549 
.34343: xorl %r12d, %r12d 
.34346: xorl %ebx, %ebx 
.34348: jmp .33756 
.34353: movl $1, %r15d 
.34359: jmp .33348 
.34364: hlt 
