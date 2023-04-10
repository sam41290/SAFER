.55547: nopl (%rax, %rax) 
.55552: endbr64 
.55556: pushq %r15 
.55558: pushq %r14 
.55560: pushq %r13 
.55562: pushq %r12 
.55564: pushq %rbp 
.55565: movl %esi, %ebp 
.55567: andl $3, %esi 
.55570: pushq %rbx 
.55571: subq $0xe8, %rsp 
.55578: movq %fs:0x28, %rax 
.55587: movq %rax, 0xd8(%rsp) 
.55595: xorl %eax, %eax 
.55597: leal -1(%rsi), %eax 
.55600: movl %esi, 0x14(%rsp) 
.55604: testl %eax, %esi 
.55606: jne .56848 
.55612: movq %rdi, %r15 
.55615: testq %rdi, %rdi 
.55618: je .56848 
.55624: movzbl (%rdi), %eax 
.55627: testb %al, %al 
.55629: je .57032 
.55635: cmpb $0x2f, %al 
.55637: je .56188 
.55643: callq .89248 
.55648: movq %rax, %r14 
.55651: testq %rax, %rax 
.55654: je .56144 
.55660: movq %rax, %rdi 
.55663: callq .18624 
.55668: movq %rax, %r13 
.55671: cmpq $0xfff, %rax 
.55677: jbe .57051 
.55683: addq %r14, %r13 
.55686: movq %r13, %rbx 
.55689: movzbl (%r15), %eax 
.55693: testb %al, %al 
.55695: je .57250 
.55701: movq %r15, 0x28(%rsp) 
.55706: andl $4, %ebp 
.55709: movq $0, 0x18(%rsp) 
.55718: movq $0, 0x38(%rsp) 
.55727: movq $0, 0x30(%rsp) 
.55736: movl %ebp, 0x24(%rsp) 
.55740: movq %r13, %rbp 
.55743: movq %r15, %r13 
.55746: setne 0x23(%rsp) 
.55751: nopw (%rax, %rax) 
.55760: movl %eax, %ecx 
.55762: cmpb $0x2f, %al 
.55764: jne .55798 
.55766: nopw %cs:(%rax, %rax) 
.55776: movzbl 1(%r13), %ecx 
.55781: addq $1, %r13 
.55785: cmpb $0x2f, %cl 
.55788: je .55776 
.55790: testb %cl, %cl 
.55792: je .56048 
.55798: movq %r13, %r15 
.55801: nopl (%rax) 
.55808: movq %r15, %r12 
.55811: movzbl 1(%r15), %eax 
.55816: addq $1, %r15 
.55820: testb %al, %al 
.55822: je .55828 
.55824: cmpb $0x2f, %al 
.55826: jne .55808 
.55828: cmpq %r13, %r15 
.55831: je .56048 
.55837: movq %r15, %rdx 
.55840: subq %r13, %rdx 
.55843: cmpq $1, %rdx 
.55847: je .56432 
.55853: cmpq $2, %rdx 
.55857: jne .55868 
.55859: cmpb $0x2e, %cl 
.55862: je .56776 
.55868: cmpb $0x2f, -1(%rbp) 
.55872: je .55882 
.55874: movb $0x2f, (%rbp) 
.55878: addq $1, %rbp 
.55882: leaq (%rbp, %rdx), %rax 
.55887: cmpq %rax, %rbx 
.55890: ja .55951 
.55892: subq %r14, %rbx 
.55895: subq %r14, %rbp 
.55898: movq %r14, %rdi 
.55901: movq %rdx, 8(%rsp) 
.55906: leaq 1(%rdx, %rbx), %rax 
.55911: addq $0x1000, %rbx 
.55918: cmpq $0x1000, %rdx 
.55925: cmovgeq %rax, %rbx 
.55929: movq %rbx, %rsi 
.55932: callq .88352 
.55937: movq 8(%rsp), %rdx 
.55942: movq %rax, %r14 
.55945: addq %rax, %rbx 
.55948: addq %rax, %rbp 
.55951: movq %rbp, %rdi 
.55954: movq %r13, %rsi 
.55957: movq %rdx, 8(%rsp) 
.55962: callq .19168 
.55967: movq 8(%rsp), %rdx 
.55972: cmpl $2, 0x14(%rsp) 
.55977: leaq (%rbp, %rdx), %rbp 
.55982: movb $0, (%rbp) 
.55986: jne .56256 
.55992: cmpb $0, 0x23(%rsp) 
.55997: je .56256 
.56003: movl $0, 0x58(%rsp) 
.56011: cmpb $0, (%r15) 
.56015: je .56028 
.56017: cmpl $2, 0x14(%rsp) 
.56022: jne .57232 
.56028: movzbl (%r15), %eax 
.56032: movq %r15, %r13 
.56035: testb %al, %al 
.56037: jne .55760 
.56043: nopl (%rax, %rax) 
.56048: movq %rbp, %r13 
.56051: leaq 1(%r14), %rax 
.56055: cmpq %rax, %r13 
.56058: jbe .56071 
.56060: cmpb $0x2f, -1(%r13) 
.56065: je .57176 
.56071: leaq 1(%r13), %rax 
.56075: movb $0, (%r13) 
.56080: cmpq %rbx, %rax 
.56083: je .56106 
.56085: movq %r13, %r9 
.56088: movq %r14, %rdi 
.56091: subq %r14, %r9 
.56094: leaq 1(%r9), %rsi 
.56098: callq .88352 
.56103: movq %rax, %r14 
.56106: movq 0x30(%rsp), %rdi 
.56111: callq .18128 
.56116: movq 0x18(%rsp), %rax 
.56121: testq %rax, %rax 
.56124: je .56144 
.56126: movq %rax, %rdi 
.56129: callq .63104 
.56134: nopw %cs:(%rax, %rax) 
.56144: movq 0xd8(%rsp), %rax 
.56152: xorq %fs:0x28, %rax 
.56161: jne .57273 
.56167: addq $0xe8, %rsp 
.56174: movq %r14, %rax 
.56177: popq %rbx 
.56178: popq %rbp 
.56179: popq %r12 
.56181: popq %r13 
.56183: popq %r14 
.56185: popq %r15 
.56187: ret 
.56188: movl $0x1000, %edi 
.56193: callq .88256 
.56198: movb $0x2f, (%rax) 
.56201: movq %rax, %r14 
.56204: leaq 0x1000(%rax), %rbx 
.56211: leaq 1(%rax), %r13 
.56215: movzbl (%r15), %eax 
.56219: testb %al, %al 
.56221: jne .55701 
.56227: movq $0, 0x18(%rsp) 
.56236: movq $0, 0x30(%rsp) 
.56245: jmp .56071 
.56256: movl 0x24(%rsp), %eax 
.56260: leaq 0x40(%rsp), %r13 
.56265: movq %r14, %rsi 
.56268: movl $1, %edi 
.56273: movq %r13, %rdx 
.56276: testl %eax, %eax 
.56278: je .56456 
.56284: callq .19264 
.56289: testl %eax, %eax 
.56291: setne %al 
.56294: testb %al, %al 
.56296: je .56392 
.56298: callq .18272 
.56303: movl (%rax), %edx 
.56305: movq %rax, %r13 
.56308: movl 0x14(%rsp), %eax 
.56312: testl %eax, %eax 
.56314: je .56928 
.56320: cmpl $1, %eax 
.56323: jne .56003 
.56329: leaq .105219(%rip), %rsi 
.56336: movq %r15, %rdi 
.56339: movl %edx, 8(%rsp) 
.56343: callq .18960 
.56348: movl 8(%rsp), %edx 
.56352: cmpb $0, (%r15, %rax) 
.56357: jne .56928 
.56363: cmpl $2, %edx 
.56366: jne .56928 
.56372: movzbl 1(%r12), %eax 
.56378: movq %r15, %r13 
.56381: jmp .56035 
.56392: movl 0x58(%rsp), %eax 
.56396: andl $0xf000, %eax 
.56401: cmpl $0xa000, %eax 
.56406: je .56480 
.56408: cmpl $0x4000, %eax 
.56413: je .56028 
.56419: jmp .56011 
.56432: cmpb $0x2e, %cl 
.56435: jne .55868 
.56441: movq %r15, %r13 
.56444: jmp .56035 
.56456: callq .18640 
.56461: testl %eax, %eax 
.56463: setne %al 
.56466: jmp .56294 
.56480: cmpq $0, 0x18(%rsp) 
.56486: je .56867 
.56492: movq 0x28(%rsp), %rsi 
.56497: movq 0x18(%rsp), %rdi 
.56502: movq %r13, %rdx 
.56505: callq .58144 
.56510: testb %al, %al 
.56512: jne .56693 
.56518: movq 0x28(%rsp), %rsi 
.56523: movq 0x18(%rsp), %rdi 
.56528: movq %r13, %rdx 
.56531: callq .58000 
.56536: movq 0x70(%rsp), %rsi 
.56541: movq %r14, %rdi 
.56544: callq .54240 
.56549: movq %rax, %r13 
.56552: testq %rax, %rax 
.56555: je .57082 
.56561: movq %rax, %rdi 
.56564: callq .18624 
.56569: movq %r15, %rdi 
.56572: movq %rax, %r12 
.56575: callq .18624 
.56580: cmpq $0, 0x38(%rsp) 
.56586: movq %rax, %rdx 
.56589: je .56976 
.56595: leaq 1(%r12, %rax), %rcx 
.56600: cmpq 0x38(%rsp), %rcx 
.56605: ja .57128 
.56611: movq 0x30(%rsp), %rax 
.56616: addq $1, %rdx 
.56620: movq %r15, %rsi 
.56623: leaq (%rax, %r12), %rdi 
.56627: callq .19536 
.56632: movq 0x30(%rsp), %rdi 
.56637: movq %r12, %rdx 
.56640: movq %r13, %rsi 
.56643: callq .19168 
.56648: cmpb $0x2f, (%r13) 
.56653: movq %rax, 0x28(%rsp) 
.56658: movq %rax, %r15 
.56661: leaq 1(%r14), %rax 
.56665: je .57116 
.56671: cmpq %rax, %rbp 
.56674: ja .57188 
.56680: movq %r13, %rdi 
.56683: callq .18128 
.56688: jmp .56028 
.56693: cmpl $2, 0x14(%rsp) 
.56698: je .56372 
.56704: callq .18272 
.56709: movl $0x28, %edx 
.56714: movq %rax, %r15 
.56717: movq 0x30(%rsp), %rdi 
.56722: movl %edx, 8(%rsp) 
.56726: callq .18128 
.56731: movq %r14, %rdi 
.56734: callq .18128 
.56739: movl 8(%rsp), %edx 
.56743: movq 0x18(%rsp), %rdi 
.56748: movl %edx, 8(%rsp) 
.56752: callq .63104 
.56757: movl 8(%rsp), %edx 
.56761: movl %edx, (%r15) 
.56764: xorl %r14d, %r14d 
.56767: jmp .56144 
.56776: cmpb $0x2e, 1(%r13) 
.56781: jne .55868 
.56787: leaq 1(%r14), %rdx 
.56791: movq %r15, %r13 
.56794: cmpq %rdx, %rbp 
.56797: jbe .56035 
.56803: subq $1, %rbp 
.56807: cmpq %r14, %rbp 
.56810: jbe .56035 
.56816: cmpb $0x2f, -1(%rbp) 
.56820: je .56441 
.56826: subq $1, %rbp 
.56830: cmpq %r14, %rbp 
.56833: jne .56816 
.56835: jmp .56441 
.56848: callq .18272 
.56853: xorl %r14d, %r14d 
.56856: movl $0x16, (%rax) 
.56862: jmp .56144 
.56867: leaq .65216(%rip), %r8 
.56874: leaq .65152(%rip), %rcx 
.56881: xorl %esi, %esi 
.56883: movl $7, %edi 
.56888: leaq .65024(%rip), %rdx 
.56895: callq .62656 
.56900: movq %rax, 0x18(%rsp) 
.56905: testq %rax, %rax 
.56908: jne .56492 
.56914: hlt 
.56928: movq %r13, %r15 
.56931: movq 0x30(%rsp), %rdi 
.56936: movl %edx, 8(%rsp) 
.56940: callq .18128 
.56945: movq %r14, %rdi 
.56948: callq .18128 
.56953: cmpq $0, 0x18(%rsp) 
.56959: movl 8(%rsp), %edx 
.56963: je .56761 
.56969: jmp .56743 
.56976: leaq 1(%r12, %rax), %rax 
.56981: movq %rdx, 8(%rsp) 
.56986: movq %rax, %rdi 
.56989: cmpq $0x1000, %rax 
.56995: movl $0x1000, %eax 
.57000: cmovaeq %rdi, %rax 
.57004: movq %rax, %rdi 
.57007: movq %rax, 0x38(%rsp) 
.57012: callq .88256 
.57017: movq 8(%rsp), %rdx 
.57022: movq %rax, 0x30(%rsp) 
.57027: jmp .56611 
.57032: callq .18272 
.57037: xorl %r14d, %r14d 
.57040: movl $2, (%rax) 
.57046: jmp .56144 
.57051: movq %r14, %rdi 
.57054: movl $0x1000, %esi 
.57059: callq .88352 
.57064: movq %rax, %r14 
.57067: addq %rax, %r13 
.57070: leaq 0x1000(%rax), %rbx 
.57077: jmp .55689 
.57082: callq .18272 
.57087: cmpl $2, 0x14(%rsp) 
.57092: movl (%rax), %edx 
.57094: movq %rax, %r13 
.57097: jne .57108 
.57099: cmpl $0xc, %edx 
.57102: jne .56372 
.57108: movq %r13, %r15 
.57111: jmp .56717 
.57116: movb $0x2f, (%r14) 
.57120: movq %rax, %rbp 
.57123: jmp .56680 
.57128: movq 0x30(%rsp), %rdi 
.57133: movq %rcx, %rsi 
.57136: movq %rcx, 8(%rsp) 
.57141: movq %rax, 0x28(%rsp) 
.57146: callq .88352 
.57151: movq 8(%rsp), %rcx 
.57156: movq 0x28(%rsp), %rdx 
.57161: movq %rax, 0x30(%rsp) 
.57166: movq %rcx, 0x38(%rsp) 
.57171: jmp .56611 
.57176: movq %r13, %rax 
.57179: subq $1, %r13 
.57183: jmp .56075 
.57188: subq $1, %rbp 
.57192: cmpq %rbp, %r14 
.57195: jae .56680 
.57201: cmpb $0x2f, -1(%rbp) 
.57205: je .56680 
.57211: subq $1, %rbp 
.57215: cmpq %rbp, %r14 
.57218: jne .57201 
.57220: jmp .56680 
.57232: callq .18272 
.57237: movl $0x14, %edx 
.57242: movq %rax, %r15 
.57245: jmp .56931 
.57250: movq $0, 0x18(%rsp) 
.57259: movq $0, 0x30(%rsp) 
.57268: jmp .56051 
.57273: hlt 
