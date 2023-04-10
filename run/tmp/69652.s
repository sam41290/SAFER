.69652: nopw %cs:(%rax, %rax) 
.69662: nop 
.69664: endbr64 
.69668: pushq %r15 
.69670: pushq %r14 
.69672: pushq %r13 
.69674: movq %rdi, %r13 
.69677: pushq %r12 
.69679: pushq %rbp 
.69680: movl %r9d, %ebp 
.69683: pushq %rbx 
.69684: movq %rsi, %rbx 
.69687: subq $0x38, %rsp 
.69691: movl %r8d, 0x28(%rsp) 
.69696: movq %rdx, 0x18(%rsp) 
.69701: movq %rcx, 0x10(%rsp) 
.69706: callq .18624 
.69711: movq %rax, %r8 
.69714: testb $2, %bpl 
.69718: je .70056 
.69724: movq %r8, %r12 
.69727: xorl %r15d, %r15d 
.69730: xorl %r14d, %r14d 
.69733: movq 0x10(%rsp), %rax 
.69738: movq (%rax), %rdx 
.69741: cmpq %r12, %rdx 
.69744: jae .70003 
.69750: movq %rdx, %r8 
.69753: xorl %eax, %eax 
.69755: movq 0x10(%rsp), %rcx 
.69760: movq %rdx, (%rcx) 
.69763: movl 0x28(%rsp), %ecx 
.69767: testl %ecx, %ecx 
.69769: je .70041 
.69775: xorl %r12d, %r12d 
.69778: cmpl $1, %ecx 
.69781: je .69795 
.69783: movq %rax, %r12 
.69786: andl $1, %eax 
.69789: shrq $1, %r12 
.69792: addq %r12, %rax 
.69795: leaq (%rax, %r8), %rcx 
.69799: testb $4, %bpl 
.69803: je .69810 
.69805: movq %r8, %rcx 
.69808: xorl %eax, %eax 
.69810: movq 0x18(%rsp), %rsi 
.69815: andl $8, %ebp 
.69818: movl $0, %edx 
.69823: cmovneq %rdx, %r12 
.69827: testq %rsi, %rsi 
.69830: je .69963 
.69836: leaq -1(%rbx, %rsi), %rbp 
.69841: movq %rbx, %rdi 
.69844: cmpq %rbp, %rbx 
.69847: jae .69880 
.69849: testq %rax, %rax 
.69852: jne .69861 
.69854: jmp .69880 
.69856: cmpq %rdi, %rbp 
.69859: jbe .69880 
.69861: addq $1, %rdi 
.69865: movq %rbx, %rdx 
.69868: movb $0x20, -1(%rdi) 
.69872: subq %rdi, %rdx 
.69875: addq %rax, %rdx 
.69878: jne .69856 
.69880: movq %rbp, %rdx 
.69883: movb $0, (%rdi) 
.69886: movq %r13, %rsi 
.69889: subq %rdi, %rdx 
.69892: movq %rcx, 8(%rsp) 
.69897: cmpq %r8, %rdx 
.69900: cmovaq %r8, %rdx 
.69904: callq .19520 
.69909: movq 8(%rsp), %rcx 
.69914: cmpq %rax, %rbp 
.69917: movq %rax, %rdx 
.69920: jbe .69960 
.69922: testq %r12, %r12 
.69925: jne .69941 
.69927: jmp .69960 
.69936: cmpq %rdx, %rbp 
.69939: jbe .69960 
.69941: addq $1, %rdx 
.69945: movq %r12, %rsi 
.69948: movb $0x20, -1(%rdx) 
.69952: subq %rdx, %rsi 
.69955: addq %rax, %rsi 
.69958: jne .69936 
.69960: movb $0, (%rdx) 
.69963: addq %rcx, %r12 
.69966: movq %r15, %rdi 
.69969: callq .18128 
.69974: movq %r14, %rdi 
.69977: callq .18128 
.69982: addq $0x38, %rsp 
.69986: movq %r12, %rax 
.69989: popq %rbx 
.69990: popq %rbp 
.69991: popq %r12 
.69993: popq %r13 
.69995: popq %r14 
.69997: popq %r15 
.69999: ret 
.70000: xorl %r14d, %r14d 
.70003: cmpq %rdx, %r12 
.70006: jae .70623 
.70012: movq 0x10(%rsp), %rcx 
.70017: movq %rdx, %rax 
.70020: movq %r12, %rdx 
.70023: subq %r12, %rax 
.70026: movq %rdx, (%rcx) 
.70029: movl 0x28(%rsp), %ecx 
.70033: testl %ecx, %ecx 
.70035: jne .69775 
.70041: movq %rax, %r12 
.70044: xorl %eax, %eax 
.70046: jmp .69795 
.70056: movq %rax, 8(%rsp) 
.70061: movq %rax, %r14 
.70064: callq .18608 
.70069: movq 8(%rsp), %r8 
.70074: cmpq $1, %rax 
.70078: jbe .69724 
.70084: xorl %edx, %edx 
.70086: xorl %edi, %edi 
.70088: movq %r13, %rsi 
.70091: callq .18448 
.70096: movq 8(%rsp), %r8 
.70101: cmpq $-1, %rax 
.70105: jne .70144 
.70107: testb $1, %bpl 
.70111: jne .69724 
.70117: xorl %r15d, %r15d 
.70120: xorl %r14d, %r14d 
.70123: movq $-1, %r12 
.70130: jmp .69966 
.70144: leaq 1(%rax), %r12 
.70148: movq %r8, 8(%rsp) 
.70153: leaq (, %r12, 4), %rax 
.70161: movq %rax, %rdi 
.70164: movq %rax, 0x20(%rsp) 
.70169: callq .18144 
.70174: movq 8(%rsp), %r8 
.70179: testq %rax, %rax 
.70182: movq %rax, %r15 
.70185: je .70547 
.70191: movq %r12, %rdx 
.70194: movq %r13, %rsi 
.70197: movq %rax, %rdi 
.70200: movq %r8, 8(%rsp) 
.70205: callq .18448 
.70210: movq 8(%rsp), %r8 
.70215: testq %rax, %rax 
.70218: je .70557 
.70224: movq 0x20(%rsp), %rax 
.70229: movl $0, -4(%r15, %rax) 
.70238: movl (%r15), %edi 
.70241: testl %edi, %edi 
.70243: je .70568 
.70249: movb $0, 0x2f(%rsp) 
.70254: movq %r15, %rdx 
.70257: nopl (%rax) 
.70264: movq %rdx, 0x20(%rsp) 
.70269: movq %r8, 8(%rsp) 
.70274: callq .19792 
.70279: movq 8(%rsp), %r8 
.70284: movq 0x20(%rsp), %rdx 
.70289: testl %eax, %eax 
.70291: jne .70304 
.70293: movl $0xfffd, (%rdx) 
.70299: movb $1, 0x2f(%rsp) 
.70304: movl 4(%rdx), %edi 
.70307: addq $4, %rdx 
.70311: testl %edi, %edi 
.70313: jne .70264 
.70315: movq %r12, %rsi 
.70318: movq %r15, %rdi 
.70321: movq %r8, 8(%rsp) 
.70326: callq .18416 
.70331: cmpb $0, 0x2f(%rsp) 
.70336: movq 8(%rsp), %r8 
.70341: movslq %eax, %r12 
.70344: je .70592 
.70350: xorl %edx, %edx 
.70352: movq %r15, %rsi 
.70355: xorl %edi, %edi 
.70357: movq %r8, 8(%rsp) 
.70362: callq .19632 
.70367: movq 8(%rsp), %r8 
.70372: addq $1, %rax 
.70376: movq %rax, 0x20(%rsp) 
.70381: movq 0x20(%rsp), %rdi 
.70386: movq %r8, 8(%rsp) 
.70391: callq .18144 
.70396: movq 8(%rsp), %r8 
.70401: testq %rax, %rax 
.70404: movq %rax, %r14 
.70407: je .70633 
.70413: movq 0x10(%rsp), %rax 
.70418: movl (%r15), %edi 
.70421: movq %r15, %r13 
.70424: xorl %r12d, %r12d 
.70427: movq (%rax), %rax 
.70430: movq %rax, 8(%rsp) 
.70435: testl %edi, %edi 
.70437: jne .70475 
.70439: jmp .70512 
.70448: cltq 
.70450: addq %r12, %rax 
.70453: cmpq %rax, 8(%rsp) 
.70458: jb .70512 
.70460: movl 4(%r13), %edi 
.70464: addq $4, %r13 
.70468: movq %rax, %r12 
.70471: testl %edi, %edi 
.70473: je .70512 
.70475: callq .19296 
.70480: cmpl $-1, %eax 
.70483: jne .70448 
.70485: movl $1, %eax 
.70490: movl $0xfffd, (%r13) 
.70498: addq %r12, %rax 
.70501: cmpq %rax, 8(%rsp) 
.70506: jae .70460 
.70508: nopl (%rax) 
.70512: movl $0, (%r13) 
.70520: movq 0x20(%rsp), %rdx 
.70525: movq %r15, %rsi 
.70528: movq %r14, %rdi 
.70531: movq %r14, %r13 
.70534: callq .19632 
.70539: movq %rax, %r8 
.70542: jmp .69733 
.70547: testb $1, %bpl 
.70551: je .70117 
.70557: movq %r8, %r12 
.70560: xorl %r14d, %r14d 
.70563: jmp .69733 
.70568: movq %r12, %rsi 
.70571: movq %r15, %rdi 
.70574: movq %r8, 8(%rsp) 
.70579: callq .18416 
.70584: movq 8(%rsp), %r8 
.70589: movslq %eax, %r12 
.70592: movq 0x10(%rsp), %rax 
.70597: movq (%rax), %rdx 
.70600: cmpq %r12, %rdx 
.70603: jae .70000 
.70609: leaq 1(%r14), %rax 
.70613: movq %rax, 0x20(%rsp) 
.70618: jmp .70381 
.70623: movq %r12, %rdx 
.70626: xorl %eax, %eax 
.70628: jmp .69755 
.70633: testb $1, %bpl 
.70637: jne .69733 
.70643: orq $0xffffffffffffffff, %r12 
.70647: jmp .69966 
