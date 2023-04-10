.19744: endbr64 
.19748: bnd jmpq *.143232(%rip) 
.19937: hlt 
.86644: movq %rcx, %r9 
.86647: movq %rdx, %r8 
.86650: movq %rsi, %rcx 
.86653: xorl %eax, %eax 
.86655: leaq .117096(%rip), %rdx 
.86662: movl $1, %esi 
.86667: callq .19744 
.86672: xorl %edi, %edi 
.86674: movl $5, %edx 
.86679: leaq .117115(%rip), %rsi 
.86686: callq .18592 
.86691: movl $0x7e2, %r8d 
.86697: movl $1, %esi 
.86702: movq %rbp, %rdi 
.86705: movq %rax, %rcx 
.86708: leaq .117920(%rip), %rdx 
.86715: xorl %eax, %eax 
.86717: callq .19744 
.86722: xorl %edi, %edi 
.86724: movl $5, %edx 
.86729: leaq .117256(%rip), %rsi 
.86736: callq .18592 
.86741: movq %rbp, %rsi 
.86744: movq %rax, %rdi 
.86747: callq .19024 
.86752: cmpq $9, %r12 
.86756: ja .87620 
.86762: leaq .117860(%rip), %rdx 
.86769: movslq (%rdx, %r12, 4), %rax 
.86773: addq %rdx, %rax 
.86776: jmpq *%rax 
.86784: movq %rcx, %r8 
.86787: movl $1, %esi 
.86792: movq %rdx, %rcx 
.86795: xorl %eax, %eax 
.86797: leaq .117108(%rip), %rdx 
.86804: callq .19744 
.86809: jmp .86672 
.86816: movq 0x38(%rbx), %r10 
.86820: movq 0x30(%rbx), %r9 
.86824: movl $5, %edx 
.86829: xorl %edi, %edi 
.86831: movq 0x28(%rbx), %r8 
.86835: movq 0x20(%rbx), %rcx 
.86839: leaq .117624(%rip), %rsi 
.86846: movq 0x18(%rbx), %r15 
.86850: movq 0x10(%rbx), %r14 
.86854: movq %r10, 0x20(%rsp) 
.86859: movq 8(%rbx), %r13 
.86863: movq (%rbx), %r12 
.86866: movq %r9, 0x18(%rsp) 
.86871: movq %r8, 0x10(%rsp) 
.86876: movq %rcx, 8(%rsp) 
.86881: callq .18592 
.86886: subq $8, %rsp 
.86890: movq %rax, %rdx 
.86893: movq 0x28(%rsp), %r10 
.86898: movq %rbp, %rdi 
.86901: movl $1, %esi 
.86906: xorl %eax, %eax 
.86908: pushq %r10 
.86910: movq 0x28(%rsp), %r9 
.86915: pushq %r9 
.86917: movq 0x28(%rsp), %r8 
.86922: movq %r14, %r9 
.86925: pushq %r8 
.86927: movq 0x28(%rsp), %rcx 
.86932: movq %r13, %r8 
.86935: pushq %rcx 
.86936: movq %r12, %rcx 
.86939: pushq %r15 
.86941: callq .19744 
.86946: addq $0x30, %rsp 
.86950: addq $0x38, %rsp 
.86954: popq %rbx 
.86955: popq %rbp 
.86956: popq %r12 
.86958: popq %r13 
.86960: popq %r14 
.86962: popq %r15 
.86964: ret 
.86968: movq 0x40(%rbx), %r11 
.86972: movq 0x38(%rbx), %r10 
.86976: movl $5, %edx 
.86981: leaq .117672(%rip), %rsi 
.86988: movq 0x30(%rbx), %r9 
.86992: movq 0x28(%rbx), %r8 
.86996: movq 0x20(%rbx), %rcx 
.87000: movq 0x18(%rbx), %r15 
.87004: movq %r11, 0x28(%rsp) 
.87009: movq 0x10(%rbx), %r14 
.87013: movq 8(%rbx), %r13 
.87017: movq %r10, 0x20(%rsp) 
.87022: movq %r9, 0x18(%rsp) 
.87027: movq (%rbx), %r12 
.87030: movq %r8, 0x10(%rsp) 
.87035: movq %rcx, 8(%rsp) 
.87040: xorl %edi, %edi 
.87042: callq .18592 
.87047: movq 0x28(%rsp), %r11 
.87052: movq %rax, %rdx 
.87055: pushq %r11 
.87057: jmp .86893 
.87072: movq (%rbx), %r12 
.87075: movl $5, %edx 
.87080: leaq .117119(%rip), %rsi 
.87087: xorl %edi, %edi 
.87089: callq .18592 
.87094: addq $0x38, %rsp 
.87098: movq %rbp, %rdi 
.87101: movl $1, %esi 
.87106: popq %rbx 
.87107: movq %rax, %rdx 
.87110: popq %rbp 
.87111: movq %r12, %rcx 
.87114: xorl %eax, %eax 
.87116: popq %r12 
.87118: popq %r13 
.87120: popq %r14 
.87122: popq %r15 
.87124: jmp .19744 
.87136: movq 8(%rbx), %r13 
.87140: movq (%rbx), %r12 
.87143: movl $5, %edx 
.87148: xorl %edi, %edi 
.87150: leaq .117135(%rip), %rsi 
.87157: callq .18592 
.87162: addq $0x38, %rsp 
.87166: movq %r13, %r8 
.87169: movq %r12, %rcx 
.87172: popq %rbx 
.87173: movq %rax, %rdx 
.87176: movq %rbp, %rdi 
.87179: movl $1, %esi 
.87184: popq %rbp 
.87185: xorl %eax, %eax 
.87187: popq %r12 
.87189: popq %r13 
.87191: popq %r14 
.87193: popq %r15 
.87195: jmp .19744 
.87200: movq 0x10(%rbx), %r14 
.87204: movq 8(%rbx), %r13 
.87208: movl $5, %edx 
.87213: xorl %edi, %edi 
.87215: movq (%rbx), %r12 
.87218: leaq .117158(%rip), %rsi 
.87225: callq .18592 
.87230: addq $0x38, %rsp 
.87234: movq %r14, %r9 
.87237: movq %r13, %r8 
.87240: popq %rbx 
.87241: movq %rax, %rdx 
.87244: movq %r12, %rcx 
.87247: movq %rbp, %rdi 
.87250: movl $1, %esi 
.87255: popq %rbp 
.87256: xorl %eax, %eax 
.87258: popq %r12 
.87260: popq %r13 
.87262: popq %r14 
.87264: popq %r15 
.87266: jmp .19744 
.87280: movl $5, %edx 
.87285: xorl %edi, %edi 
.87287: movq 0x18(%rbx), %r15 
.87291: movq 0x10(%rbx), %r14 
.87295: leaq .117464(%rip), %rsi 
.87302: movq 8(%rbx), %r13 
.87306: movq (%rbx), %r12 
.87309: callq .18592 
.87314: subq $8, %rsp 
.87318: movq %rax, %rdx 
.87321: pushq %r15 
.87323: movq %r14, %r9 
.87326: movq %r13, %r8 
.87329: movq %r12, %rcx 
.87332: movq %rbp, %rdi 
.87335: movl $1, %esi 
.87340: xorl %eax, %eax 
.87342: callq .19744 
.87347: popq %rax 
.87348: popq %rdx 
.87349: addq $0x38, %rsp 
.87353: popq %rbx 
.87354: popq %rbp 
.87355: popq %r12 
.87357: popq %r13 
.87359: popq %r14 
.87361: popq %r15 
.87363: ret 
.87368: movq 0x20(%rbx), %rcx 
.87372: movl $5, %edx 
.87377: xorl %edi, %edi 
.87379: movq 0x18(%rbx), %r15 
.87383: leaq .117496(%rip), %rsi 
.87390: movq 0x10(%rbx), %r14 
.87394: movq 8(%rbx), %r13 
.87398: movq %rcx, 8(%rsp) 
.87403: movq (%rbx), %r12 
.87406: callq .18592 
.87411: movq 8(%rsp), %rcx 
.87416: movq %rax, %rdx 
.87419: pushq %rcx 
.87420: jmp .87321 
.87424: movq 0x28(%rbx), %r8 
.87428: movq 0x20(%rbx), %rcx 
.87432: movl $5, %edx 
.87437: xorl %edi, %edi 
.87439: leaq .117536(%rip), %rsi 
.87446: movq 0x18(%rbx), %r15 
.87450: movq 0x10(%rbx), %r14 
.87454: movq 8(%rbx), %r13 
.87458: movq (%rbx), %r12 
.87461: movq %r8, 0x10(%rsp) 
.87466: movq %rcx, 8(%rsp) 
.87471: callq .18592 
.87476: subq $8, %rsp 
.87480: movq %rax, %rdx 
.87483: movq 0x18(%rsp), %r8 
.87488: movq %r14, %r9 
.87491: movq %rbp, %rdi 
.87494: movl $1, %esi 
.87499: xorl %eax, %eax 
.87501: pushq %r8 
.87503: movq 0x18(%rsp), %rcx 
.87508: movq %r13, %r8 
.87511: pushq %rcx 
.87512: movq %r12, %rcx 
.87515: pushq %r15 
.87517: callq .19744 
.87522: addq $0x20, %rsp 
.87526: addq $0x38, %rsp 
.87530: popq %rbx 
.87531: popq %rbp 
.87532: popq %r12 
.87534: popq %r13 
.87536: popq %r14 
.87538: popq %r15 
.87540: ret 
.87544: movq 0x30(%rbx), %r9 
.87548: movq 0x28(%rbx), %r8 
.87552: movl $5, %edx 
.87557: xorl %edi, %edi 
.87559: movq 0x20(%rbx), %rcx 
.87563: leaq .117576(%rip), %rsi 
.87570: movq 0x18(%rbx), %r15 
.87574: movq 0x10(%rbx), %r14 
.87578: movq 8(%rbx), %r13 
.87582: movq %r9, 0x18(%rsp) 
.87587: movq %r8, 0x10(%rsp) 
.87592: movq (%rbx), %r12 
.87595: movq %rcx, 8(%rsp) 
.87600: callq .18592 
.87605: movq 0x18(%rsp), %r9 
.87610: movq %rax, %rdx 
.87613: pushq %r9 
.87615: jmp .87483 
.87620: movq 0x40(%rbx), %r11 
.87624: movq 0x38(%rbx), %r10 
.87628: movl $5, %edx 
.87633: leaq .117728(%rip), %rsi 
.87640: movq 0x30(%rbx), %r9 
.87644: movq 0x28(%rbx), %r8 
.87648: movq 0x20(%rbx), %rcx 
.87652: movq 0x18(%rbx), %r15 
.87656: movq %r11, 0x28(%rsp) 
.87661: movq 0x10(%rbx), %r14 
.87665: movq 8(%rbx), %r13 
.87669: movq %r10, 0x20(%rsp) 
.87674: movq %r9, 0x18(%rsp) 
.87679: movq (%rbx), %r12 
.87682: movq %r8, 0x10(%rsp) 
.87687: movq %rcx, 8(%rsp) 
.87692: jmp .87040 
