.34369: nopw %cs:(%rax, %rax) 
.34380: nopl (%rax) 
.34384: pushq %r15 
.34386: pushq %r14 
.34388: pushq %r13 
.34390: pushq %r12 
.34392: pushq %rbp 
.34393: pushq %rbx 
.34394: subq $0x1000, %rsp 
.34401: orq $0, (%rsp) 
.34406: subq $0x1000, %rsp 
.34413: orq $0, (%rsp) 
.34418: subq $0x48, %rsp 
.34422: movq 0x2080(%rsp), %r14 
.34430: movq %rdi, %r13 
.34433: movq %rcx, %r12 
.34436: movl %r8d, %r15d 
.34439: movl %edx, %ecx 
.34441: movq %fs:0x28, %rax 
.34450: movq %rax, 0x2038(%rsp) 
.34458: xorl %eax, %eax 
.34460: xorl %r8d, %r8d 
.34463: leaq 0x30(%rsp), %rax 
.34468: movq %rsi, %rdx 
.34471: movq %r9, %rbx 
.34474: leaq 0x28(%rsp), %rdi 
.34479: leaq 0x27(%rsp), %r9 
.34484: movq %r13, %rsi 
.34487: movq %rax, (%rsp) 
.34491: movq %rax, 0x28(%rsp) 
.34496: callq .33248 
.34501: cmpb $0, 0x27(%rsp) 
.34506: movq %rax, %rbp 
.34509: je .34520 
.34511: testb %r15b, %r15b 
.34514: jne .35120 
.34520: testq %r12, %r12 
.34523: je .34588 
.34525: movl $4, %edi 
.34530: callq .27456 
.34535: testb %al, %al 
.34537: jne .35232 
.34543: leaq .143464(%rip), %rsi 
.34550: leaq -8(%rsi), %rdi 
.34554: callq .32752 
.34559: leaq 8(%r12), %rsi 
.34564: movq %r12, %rdi 
.34567: callq .32752 
.34572: leaq .143480(%rip), %rsi 
.34579: leaq -8(%rsi), %rdi 
.34583: callq .32752 
.34588: testq %r14, %r14 
.34591: je .35168 
.34597: movzbl .148392(%rip), %r12d 
.34605: testb %r12b, %r12b 
.34608: jne .35032 
.34614: movq %rbp, %r10 
.34617: xorl %r9d, %r9d 
.34620: movq .148360(%rip), %rdi 
.34627: xorl %esi, %esi 
.34629: movq %r10, 0x18(%rsp) 
.34634: movq %r9, 0x10(%rsp) 
.34639: callq .28832 
.34644: movl $1, %esi 
.34649: movq %r14, %rdi 
.34652: movq %rax, %r15 
.34655: callq .28832 
.34660: leaq .104446(%rip), %rcx 
.34667: movq %r15, %rdx 
.34670: leaq .104420(%rip), %rsi 
.34677: cmpb $0x2f, (%rax) 
.34680: movq %rax, %r8 
.34683: leaq .105219(%rip), %rax 
.34690: movl $1, %edi 
.34695: cmovneq %rax, %rcx 
.34699: xorl %eax, %eax 
.34701: movq %r8, 8(%rsp) 
.34706: callq .19472 
.34711: movq %r15, %rdi 
.34714: callq .18128 
.34719: movq 8(%rsp), %r8 
.34724: movq %r8, %rdi 
.34727: callq .18128 
.34732: movq 0x10(%rsp), %r9 
.34737: movq 0x18(%rsp), %r10 
.34742: testq %rbx, %rbx 
.34745: je .35186 
.34751: cmpb $0, .148248(%rip) 
.34758: je .34796 
.34760: movq 0x18(%rbx), %rdx 
.34764: movq 0x20(%rbx), %rax 
.34768: subq %rdx, %rax 
.34771: cmpq $7, %rax 
.34775: jbe .35248 
.34781: movq .147960(%rip), %rax 
.34788: movq %rax, (%rdx) 
.34791: addq $8, 0x18(%rbx) 
.34796: movq 0x28(%rsp), %rdi 
.34801: movq .144008(%rip), %rcx 
.34808: movq %r10, %rdx 
.34811: movl $1, %esi 
.34816: addq %r9, %rdi 
.34819: callq .19408 
.34824: movq .147960(%rip), %rax 
.34831: addq %rbp, %rax 
.34834: cmpb $0, .148248(%rip) 
.34841: movq %rax, .147960(%rip) 
.34848: je .34879 
.34850: movq 0x18(%rbx), %rcx 
.34854: movq 0x20(%rbx), %rdx 
.34858: subq %rcx, %rdx 
.34861: cmpq $7, %rdx 
.34865: jbe .35296 
.34871: movq %rax, (%rcx) 
.34874: addq $8, 0x18(%rbx) 
.34879: testq %r14, %r14 
.34882: je .34959 
.34884: movq .144008(%rip), %rcx 
.34891: movl $6, %edx 
.34896: movl $1, %esi 
.34901: leaq .104440(%rip), %rdi 
.34908: callq .19408 
.34913: testb %r12b, %r12b 
.34916: je .34959 
.34918: movq 0x28(%rsp), %rax 
.34923: movq .144008(%rip), %rdi 
.34930: movzbl -1(%rax, %rbp), %edx 
.34935: movq 0x28(%rdi), %rax 
.34939: cmpq 0x30(%rdi), %rax 
.34943: jae .35344 
.34949: leaq 1(%rax), %rcx 
.34953: movq %rcx, 0x28(%rdi) 
.34957: movb %dl, (%rax) 
.34959: movq 0x28(%rsp), %rdi 
.34964: cmpq %r13, %rdi 
.34967: je .34980 
.34969: cmpq (%rsp), %rdi 
.34973: je .34980 
.34975: callq .18128 
.34980: movzbl 0x27(%rsp), %eax 
.34985: addq %rbp, %rax 
.34988: movq 0x2038(%rsp), %rbx 
.34996: xorq %fs:0x28, %rbx 
.35005: jne .35404 
.35011: addq $0x2048, %rsp 
.35018: popq %rbx 
.35019: popq %rbp 
.35020: popq %r12 
.35022: popq %r13 
.35024: popq %r14 
.35026: popq %r15 
.35028: ret 
.35032: movzbl .148393(%rip), %r12d 
.35040: testb %r12b, %r12b 
.35043: je .34614 
.35049: cmpb $0, 0x27(%rsp) 
.35054: jne .35328 
.35060: movq 0x28(%rsp), %rax 
.35065: movq .144008(%rip), %rdi 
.35072: leaq -2(%rbp), %r10 
.35076: movzbl (%rax), %edx 
.35079: movq 0x28(%rdi), %rax 
.35083: cmpq 0x30(%rdi), %rax 
.35087: jae .35375 
.35093: leaq 1(%rax), %rcx 
.35097: movl $1, %r9d 
.35103: movq %rcx, 0x28(%rdi) 
.35107: movb %dl, (%rax) 
.35109: jmp .34620 
.35120: movq .144008(%rip), %rdi 
.35127: movq 0x28(%rdi), %rax 
.35131: cmpq 0x30(%rdi), %rax 
.35135: jae .35360 
.35141: leaq 1(%rax), %rdx 
.35145: movq %rdx, 0x28(%rdi) 
.35149: movb $0x20, (%rax) 
.35152: addq $1, .147960(%rip) 
.35160: jmp .34520 
.35168: movq %rbp, %r10 
.35171: xorl %r9d, %r9d 
.35174: xorl %r12d, %r12d 
.35177: testq %rbx, %rbx 
.35180: jne .34751 
.35186: movq 0x28(%rsp), %rdi 
.35191: movq .144008(%rip), %rcx 
.35198: movq %r10, %rdx 
.35201: movl $1, %esi 
.35206: addq %r9, %rdi 
.35209: callq .19408 
.35214: addq %rbp, .147960(%rip) 
.35221: jmp .34879 
.35232: callq .32864 
.35237: jmp .34543 
.35248: movl $8, %esi 
.35253: movq %rbx, %rdi 
.35256: movq %r10, 0x10(%rsp) 
.35261: movq %r9, 8(%rsp) 
.35266: callq .92864 
.35271: movq 0x18(%rbx), %rdx 
.35275: movq 0x10(%rsp), %r10 
.35280: movq 8(%rsp), %r9 
.35285: jmp .34781 
.35296: movl $8, %esi 
.35301: movq %rbx, %rdi 
.35304: callq .92864 
.35309: movq 0x18(%rbx), %rcx 
.35313: movq .147960(%rip), %rax 
.35320: jmp .34871 
.35328: movq %rbp, %r10 
.35331: xorl %r9d, %r9d 
.35334: xorl %r12d, %r12d 
.35337: jmp .34620 
.35344: movzbl %dl, %esi 
.35347: callq .18768 
.35352: jmp .34959 
.35360: movl $0x20, %esi 
.35365: callq .18768 
.35370: jmp .35152 
.35375: movzbl %dl, %esi 
.35378: movq %r10, 8(%rsp) 
.35383: callq .18768 
.35388: movq 8(%rsp), %r10 
.35393: movl $1, %r9d 
.35399: jmp .34620 
.35404: hlt 
