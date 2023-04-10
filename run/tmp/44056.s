.43773: testb %r8b, %r8b 
.43776: jne .45521 
.43782: movl .148216(%rip), %ecx 
.43788: leaq 0x18(%rbx), %r15 
.43792: cmpl $4, %ecx 
.43795: ja .44832 
.43801: cmpl $2, %ecx 
.43804: ja .45408 
.43810: movq %r15, %rdx 
.43813: movq %r14, %rsi 
.43816: movl $1, %edi 
.43821: callq .18640 
.43826: xorl %edx, %edx 
.43828: testl %eax, %eax 
.43830: jne .44870 
.43836: movb $1, 0xb8(%rbx) 
.43843: cmpl $5, %r13d 
.43847: je .45312 
.43853: movl 0x30(%rbx), %eax 
.43856: andl $0xf000, %eax 
.43861: cmpl $0x8000, %eax 
.43866: je .45312 
.43872: movl .148280(%rip), %eax 
.43878: testl %eax, %eax 
.43880: je .44928 
.43886: cmpb $0, .148325(%rip) 
.43893: jne .44928 
.43899: movl 0x30(%rbx), %eax 
.43902: andl $0xf000, %eax 
.43907: cmpl $0xa000, %eax 
.43912: je .46328 
.43918: cmpl $0x4000, %eax 
.43923: je .46352 
.43929: movl $5, 0xa8(%rbx) 
.43939: movl .148280(%rip), %r9d 
.43946: movq 0x58(%rbx), %r14 
.43950: testl %r9d, %r9d 
.43953: je .44456 
.43959: cmpb $0, .148268(%rip) 
.43966: jne .44456 
.43972: cmpb $0, .148325(%rip) 
.43979: jne .44580 
.43985: movzbl .148220(%rip), %eax 
.43992: testb %al, %al 
.43994: jne .45592 
.44000: movq %r12, %rdi 
.44003: callq .88848 
.44008: addq $1, .148400(%rip) 
.44016: movq %rax, (%rbx) 
.44019: movq -0x38(%rbp), %rax 
.44023: xorq %fs:0x28, %rax 
.44032: jne .47274 
.44038: leaq -0x28(%rbp), %rsp 
.44042: movq %r14, %rax 
.44045: popq %rbx 
.44046: popq %r12 
.44048: popq %r13 
.44050: popq %r14 
.44052: popq %r15 
.44054: popq %rbp 
.44055: ret 
.44056: nopl (%rax, %rax) 
.44064: testb %r8b, %r8b 
.44067: jne .45504 
.44073: cmpb $0, .148129(%rip) 
.44080: jne .44304 
.44086: cmpl $3, %r13d 
.44090: je .47048 
.44096: movzbl .148220(%rip), %eax 
.44103: testb %al, %al 
.44105: jne .46704 
.44111: cmpb $0, .148128(%rip) 
.44118: je .46896 
.44124: testl %r13d, %r13d 
.44127: sete %cl 
.44130: movl %ecx, %edx 
.44132: cmpl $6, %r13d 
.44136: je .46724 
.44142: testb %cl, %cl 
.44144: jne .46724 
.44150: cmpb $0, .148128(%rip) 
.44157: je .46896 
.44163: xorl %r14d, %r14d 
.44166: cmpl $5, %r13d 
.44170: jne .44000 
.44176: cmpl $3, .148244(%rip) 
.44183: je .44304 
.44185: cmpb $0, .148242(%rip) 
.44192: movb %r8b, -0x390(%rbp) 
.44199: je .44000 
.44205: movl $0xe, %edi 
.44210: callq .27456 
.44215: movzbl -0x390(%rbp), %r8d 
.44223: testb %al, %al 
.44225: jne .44304 
.44227: movl $0x10, %edi 
.44232: callq .27456 
.44237: movzbl -0x390(%rbp), %r8d 
.44245: testb %al, %al 
.44247: jne .44304 
.44249: movl $0x11, %edi 
.44254: callq .27456 
.44259: movzbl -0x390(%rbp), %r8d 
.44267: testb %al, %al 
.44269: jne .44304 
.44271: movl $0x15, %edi 
.44276: callq .27456 
.44281: movzbl -0x390(%rbp), %r8d 
.44289: testb %al, %al 
.44291: je .44000 
.44297: nopl (%rax) 
.44304: movzbl (%r12), %edx 
.44309: movq %r12, %r14 
.44312: cmpb $0x2f, %dl 
.44315: je .43782 
.44321: movzbl (%r15), %esi 
.44325: movq %r12, %r14 
.44328: testb %sil, %sil 
.44331: je .43782 
.44337: movq %r12, %rdi 
.44340: movb %dl, -0x386(%rbp) 
.44346: movb %r8b, -0x385(%rbp) 
.44353: movb %sil, -0x390(%rbp) 
.44360: callq .18624 
.44365: movq %r15, %rdi 
.44368: movq %rax, %r14 
.44371: callq .18624 
.44376: movq %rsp, %rsi 
.44379: movzbl -0x386(%rbp), %edx 
.44386: movzbl -0x385(%rbp), %r8d 
.44394: leaq 0x19(%r14, %rax), %rax 
.44399: movq %rax, %rcx 
.44402: andq $0xfffffffffffff000, %rax 
.44408: subq %rax, %rsi 
.44411: andq $0xfffffffffffffff0, %rcx 
.44415: movq %rsi, %rax 
.44418: movzbl -0x390(%rbp), %esi 
.44425: cmpq %rax, %rsp 
.44428: je .46056 
.44434: subq $0x1000, %rsp 
.44441: orq $0, 0xff8(%rsp) 
.44450: jmp .44425 
.44456: movq .148256(%rip), %r8 
.44463: movl .148264(%rip), %edx 
.44469: movl $0x200, %ecx 
.44474: movq %r14, %rdi 
.44477: leaq -0x2d0(%rbp), %r13 
.44484: movq %r13, %rsi 
.44487: callq .65440 
.44492: xorl %esi, %esi 
.44494: movq %rax, %rdi 
.44497: callq .71376 
.44502: cmpl .148316(%rip), %eax 
.44508: jle .44516 
.44510: movl %eax, .148316(%rip) 
.44516: movl .148280(%rip), %r8d 
.44523: testl %r8d, %r8d 
.44526: jne .43972 
.44532: cmpb $0, .143393(%rip) 
.44539: jne .46648 
.44545: cmpb $0, .143392(%rip) 
.44552: jne .46512 
.44558: cmpb $0, .148270(%rip) 
.44565: jne .46472 
.44571: cmpb $0, .148325(%rip) 
.44578: je .44604 
.44580: movq 0xb0(%rbx), %rdi 
.44587: callq .18624 
.44592: cmpl .148308(%rip), %eax 
.44598: jg .45856 
.44604: movl .148280(%rip), %edi 
.44610: testl %edi, %edi 
.44612: jne .43985 
.44618: movq 0x28(%rbx), %rdi 
.44622: leaq -0x2f0(%rbp), %rsi 
.44629: callq .69568 
.44634: movq %rax, %rdi 
.44637: callq .18624 
.44642: cmpl .148312(%rip), %eax 
.44648: jle .44656 
.44650: movl %eax, .148312(%rip) 
.44656: movl 0x30(%rbx), %eax 
.44659: andl $0xb000, %eax 
.44664: cmpl $0x2000, %eax 
.44669: jne .45872 
.44675: movq 0x40(%rbx), %rax 
.44679: leaq -0x2d0(%rbp), %r13 
.44686: movq %r13, %rsi 
.44689: movq %rax, %rdi 
.44692: shrq $0x20, %rax 
.44696: shrq $8, %rdi 
.44700: movl %edi, %edx 
.44702: movq %rax, %rdi 
.44705: andl $0xfff, %edx 
.44711: andl $0xfffff000, %edi 
.44717: orl %edx, %edi 
.44719: callq .69568 
.44724: movq %rax, %rdi 
.44727: callq .18624 
.44732: cmpl .148292(%rip), %eax 
.44738: jle .44746 
.44740: movl %eax, .148292(%rip) 
.44746: movq 0x40(%rbx), %rax 
.44750: movq %r13, %rsi 
.44753: movzbl %al, %edx 
.44756: shrq $0xc, %rax 
.44760: movq %rax, %rdi 
.44763: xorb %dil, %dil 
.44766: orl %edx, %edi 
.44768: callq .69568 
.44773: movq %rax, %rdi 
.44776: callq .18624 
.44781: movl .148288(%rip), %edx 
.44787: cmpl %edx, %eax 
.44789: jle .44799 
.44791: movl %eax, .148288(%rip) 
.44797: movl %eax, %edx 
.44799: movl .148292(%rip), %eax 
.44805: leal 2(%rdx, %rax), %eax 
.44809: cmpl .148284(%rip), %eax 
.44815: jle .43985 
.44821: jmp .45928 
.44832: cmpl $5, %ecx 
.44835: jne .43810 
.44841: movq %r15, %rdx 
.44844: movq %r14, %rsi 
.44847: movl $1, %edi 
.44852: callq .19264 
.44857: movl $1, %edx 
.44862: testl %eax, %eax 
.44864: je .43836 
.44870: movl $5, %edx 
.44875: leaq .104497(%rip), %rsi 
.44882: xorl %edi, %edi 
.44884: callq .18592 
.44889: movl -0x384(%rbp), %r15d 
.44896: movq %r14, %rdx 
.44899: xorl %r14d, %r14d 
.44902: movq %rax, %rsi 
.44905: movzbl %r15b, %edi 
.44909: callq .30704 
.44914: testb %r15b, %r15b 
.44917: jne .44019 
.44923: jmp .44000 
.44928: movq .144112(%rip), %rax 
.44935: cmpq %rax, 0x18(%rbx) 
.44939: je .46407 
.44945: leaq 0xb0(%rbx), %rsi 
.44952: movq %r14, %rdi 
.44955: testb %dl, %dl 
.44957: je .45648 
.44963: callq .92272 
.44968: testl %eax, %eax 
.44970: js .45661 
.44976: movq 0xb0(%rbx), %rdi 
.44983: movl $0xa, %ecx 
.44988: leaq .104543(%rip), %rsi 
.44995: repe cmpsb (%rdi), (%rsi) 
.44997: movl .148280(%rip), %ecx 
.45003: seta %al 
.45006: sbbb $0, %al 
.45008: movsbl %al, %eax 
.45011: testl %eax, %eax 
.45013: setne %dl 
.45016: testl %ecx, %ecx 
.45018: je .45944 
.45024: testl %eax, %eax 
.45026: je .46454 
.45032: movl $1, 0xbc(%rbx) 
.45042: movb $1, .148324(%rip) 
.45049: movl 0x30(%rbx), %eax 
.45052: andl $0xf000, %eax 
.45057: cmpl $0xa000, %eax 
.45062: jne .43918 
.45068: movl .148280(%rip), %r13d 
.45075: testl %r13d, %r13d 
.45078: jne .46328 
.45084: movq 0x48(%rbx), %rsi 
.45088: movq %r14, %rdi 
.45091: callq .54240 
.45096: movq %rax, 8(%rbx) 
.45100: movq %rax, %r13 
.45103: testq %rax, %rax 
.45106: je .46984 
.45112: cmpb $0x2f, (%r13) 
.45117: je .46688 
.45123: movq %r14, %rdi 
.45126: callq .57488 
.45131: testq %rax, %rax 
.45134: je .46688 
.45140: movq %r13, %rdi 
.45143: movq %rax, -0x390(%rbp) 
.45150: callq .18624 
.45155: movq -0x390(%rbp), %rdx 
.45162: leaq 2(%rdx, %rax), %rdi 
.45167: callq .88256 
.45172: movq -0x390(%rbp), %rdx 
.45179: movq %rax, %r15 
.45182: cmpb $0x2f, -1(%r14, %rdx) 
.45188: je .45194 
.45190: addq $1, %rdx 
.45194: movq %r14, %rsi 
.45197: movq %r15, %rdi 
.45200: callq .19440 
.45205: movq %r13, %rsi 
.45208: movq %rax, %rdi 
.45211: callq .18336 
.45216: testq %r15, %r15 
.45219: je .47034 
.45225: movl 0xc4(%rbx), %r11d 
.45232: testl %r11d, %r11d 
.45235: je .47200 
.45241: cmpl $1, .148244(%rip) 
.45248: ja .46200 
.45254: cmpb $0, .148221(%rip) 
.45261: jne .46200 
.45267: movq %r15, %rdi 
.45270: callq .18128 
.45275: movl 0x30(%rbx), %eax 
.45278: andl $0xf000, %eax 
.45283: cmpl $0xa000, %eax 
.45288: jne .43918 
.45294: movl $6, 0xa8(%rbx) 
.45304: jmp .43939 
.45312: cmpb $0, .148242(%rip) 
.45319: je .43872 
.45325: movl $0x15, %edi 
.45330: movb %dl, -0x390(%rbp) 
.45336: callq .27456 
.45341: movzbl -0x390(%rbp), %edx 
.45348: testb %al, %al 
.45350: je .43872 
.45356: callq .18272 
.45361: movq 0x18(%rbx), %r13 
.45365: cmpq .144120(%rip), %r13 
.45372: movl $0x5f, (%rax) 
.45378: movzbl -0x390(%rbp), %edx 
.45385: je .45394 
.45387: movq %r13, .144120(%rip) 
.45394: movb $0, 0xc0(%rbx) 
.45401: jmp .43872 
.45408: cmpb $0, -0x384(%rbp) 
.45415: je .43810 
.45421: movq %r15, %rdx 
.45424: movq %r14, %rsi 
.45427: movl $1, %edi 
.45432: movl %ecx, -0x390(%rbp) 
.45438: callq .19264 
.45443: movl -0x390(%rbp), %ecx 
.45449: cmpl $3, %ecx 
.45452: je .45483 
.45454: testl %eax, %eax 
.45456: js .46832 
.45462: movl 0x30(%rbx), %edx 
.45465: andl $0xf000, %edx 
.45471: cmpl $0x4000, %edx 
.45477: jne .43810 
.45483: testl %eax, %eax 
.45485: jne .46846 
.45491: movzbl -0x384(%rbp), %edx 
.45498: jmp .43836 
.45504: movzbl (%r12), %edx 
.45509: cmpb $0x2f, %dl 
.45512: jne .45832 
.45518: movq %r12, %r14 
.45521: movl $2, %esi 
.45526: movq %r14, %rdi 
.45529: callq .55552 
.45534: movq %rax, 0x10(%rbx) 
.45538: testq %rax, %rax 
.45541: jne .43782 
.45547: xorl %edi, %edi 
.45549: movl $5, %edx 
.45554: leaq .104473(%rip), %rsi 
.45561: callq .18592 
.45566: movzbl -0x384(%rbp), %edi 
.45573: movq %r14, %rdx 
.45576: movq %rax, %rsi 
.45579: callq .30704 
.45584: jmp .43782 
.45592: movq 0x20(%rbx), %rdi 
.45596: leaq -0x2d0(%rbp), %rsi 
.45603: callq .69568 
.45608: movq %rax, %rdi 
.45611: callq .18624 
.45616: cmpl .148320(%rip), %eax 
.45622: jle .44000 
.45628: movl %eax, .148320(%rip) 
.45634: jmp .44000 
.45648: callq .92304 
.45653: testl %eax, %eax 
.45655: jns .44976 
.45661: callq .18272 
.45666: movl (%rax), %edx 
.45668: movq %rax, %r13 
.45671: cmpl $0x5f, %edx 
.45674: leal -0x16(%rdx), %esi 
.45677: sete %cl 
.45680: andl $0xffffffef, %esi 
.45683: je .45689 
.45685: testb %cl, %cl 
.45687: je .45700 
.45689: movq 0x18(%rbx), %rax 
.45693: movq %rax, .144112(%rip) 
.45700: leaq .143394(%rip), %rax 
.45707: movq %rax, 0xb0(%rbx) 
.45714: cmpl $0x3d, %edx 
.45717: je .46440 
.45723: testb %cl, %cl 
.45725: jne .46440 
.45731: movl $0, 0xbc(%rbx) 
.45741: movq %r14, %rdx 
.45744: xorl %edi, %edi 
.45746: movl $3, %esi 
.45751: callq .85600 
.45756: movq %rax, %r13 
.45759: callq .18272 
.45764: movq %r13, %rcx 
.45767: leaq .114332(%rip), %rdx 
.45774: xorl %edi, %edi 
.45776: movl (%rax), %esi 
.45778: xorl %eax, %eax 
.45780: callq .19552 
.45785: jmp .45049 
.45832: movzbl (%r15), %esi 
.45836: movq %r12, %r14 
.45839: testb %sil, %sil 
.45842: je .45521 
.45848: jmp .44337 
.45856: movl %eax, .148308(%rip) 
.45862: jmp .44604 
.45872: movq 0x48(%rbx), %rdi 
.45876: movq .143384(%rip), %r8 
.45883: leaq -0x2d0(%rbp), %rsi 
.45890: movl $1, %ecx 
.45895: movl .148252(%rip), %edx 
.45901: callq .65440 
.45906: xorl %esi, %esi 
.45908: movq %rax, %rdi 
.45911: callq .71376 
.45916: cmpl .148284(%rip), %eax 
.45922: jle .43985 
.45928: movl %eax, .148284(%rip) 
.45934: jmp .43985 
.45944: movb %dl, -0x390(%rbp) 
.45950: callq .18272 
.45955: movzbl -0x390(%rbp), %edx 
.45962: movq %rax, %r13 
.45965: movq .144104(%rip), %rax 
.45972: cmpq %rax, 0x18(%rbx) 
.45976: je .47232 
.45982: movl $0, (%r13) 
.45990: movq %r15, %rsi 
.45993: movq %r14, %rdi 
.45996: movb %dl, -0x390(%rbp) 
.46002: callq .57808 
.46007: testl %eax, %eax 
.46009: jle .46912 
.46015: movl $1, %edx 
.46020: xorl %eax, %eax 
.46022: movl $2, %ecx 
.46027: movl %ecx, 0xbc(%rbx) 
.46033: movb %dl, .148324(%rip) 
.46039: testl %eax, %eax 
.46041: jne .45741 
.46047: jmp .45049 
.46056: andl $0xfff, %ecx 
.46062: subq %rcx, %rsp 
.46065: testq %rcx, %rcx 
.46068: jne .46816 
.46074: leaq 0xf(%rsp), %r10 
.46079: movzbl 1(%r15), %edi 
.46084: andq $0xfffffffffffffff0, %r10 
.46088: movq %r10, %r14 
.46091: cmpb $0x2e, %sil 
.46095: je .46304 
.46101: movq %r15, %rcx 
.46104: jmp .46121 
.46112: movl %edi, %esi 
.46114: movzbl 1(%rcx), %edi 
.46118: movq %rax, %r10 
.46121: leaq 1(%r10), %rax 
.46125: addq $1, %rcx 
.46129: movb %sil, -1(%rax) 
.46133: testb %dil, %dil 
.46136: jne .46112 
.46138: cmpq %rcx, %r15 
.46141: jae .46156 
.46143: cmpb $0x2f, -1(%rcx) 
.46147: je .46156 
.46149: movb $0x2f, (%rax) 
.46152: leaq 2(%r10), %rax 
.46156: testb %dl, %dl 
.46158: je .46185 
.46160: movq %r12, %rcx 
.46163: nopl (%rax, %rax) 
.46168: addq $1, %rcx 
.46172: movb %dl, (%rax) 
.46174: addq $1, %rax 
.46178: movzbl (%rcx), %edx 
.46181: testb %dl, %dl 
.46183: jne .46168 
.46185: movb $0, (%rax) 
.46188: jmp .43773 
.46200: leaq -0x380(%rbp), %rdx 
.46207: movq %r15, %rsi 
.46210: movl $1, %edi 
.46215: callq .19264 
.46220: testl %eax, %eax 
.46222: jne .45267 
.46228: cmpb $0, -0x384(%rbp) 
.46235: movb $1, 0xb9(%rbx) 
.46242: movl -0x368(%rbp), %eax 
.46248: je .46288 
.46250: movl .148280(%rip), %r10d 
.46257: testl %r10d, %r10d 
.46260: je .46288 
.46262: movl %eax, %edx 
.46264: andl $0xf000, %edx 
.46270: cmpl $0x4000, %edx 
.46276: je .45267 
.46282: nopw (%rax, %rax) 
.46288: movl %eax, 0xac(%rbx) 
.46294: jmp .45267 
.46304: movq %r10, %rax 
.46307: testb %dil, %dil 
.46310: je .46156 
.46316: jmp .46101 
.46328: cmpb $0, .148221(%rip) 
.46335: jne .45084 
.46341: jmp .45294 
.46352: cmpb $0, -0x384(%rbp) 
.46359: je .46392 
.46361: cmpb $0, .148213(%rip) 
.46368: jne .46392 
.46370: movl $9, 0xa8(%rbx) 
.46380: jmp .43939 
.46392: movl $3, 0xa8(%rbx) 
.46402: jmp .43939 
.46407: callq .18272 
.46412: movl $0x5f, (%rax) 
.46418: movq %rax, %r13 
.46421: leaq .143394(%rip), %rax 
.46428: movq %rax, 0xb0(%rbx) 
.46435: nopl (%rax, %rax) 
.46440: movl .148280(%rip), %esi 
.46446: testl %esi, %esi 
.46448: je .46800 
.46454: movl $0, 0xbc(%rbx) 
.46464: jmp .43899 
.46472: movl 0x34(%rbx), %edi 
.46475: callq .43264 
.46480: cmpl .148296(%rip), %eax 
.46486: jle .44571 
.46492: movl %eax, .148296(%rip) 
.46498: jmp .44571 
.46512: cmpb $0, .148269(%rip) 
.46519: movl 0x38(%rbx), %r15d 
.46523: je .47152 
.46529: movl %r15d, %r8d 
.46532: leaq .104408(%rip), %rcx 
.46539: movq %r13, %rdi 
.46542: xorl %eax, %eax 
.46544: movl $0x15, %edx 
.46549: movl $1, %esi 
.46554: callq .19856 
.46559: movq %r13, %rax 
.46562: movl (%rax), %ecx 
.46564: addq $4, %rax 
.46568: leal -0x1010101(%rcx), %edx 
.46574: notl %ecx 
.46576: andl %ecx, %edx 
.46578: andl $0x80808080, %edx 
.46584: je .46562 
.46586: movl %edx, %ecx 
.46588: shrl $0x10, %ecx 
.46591: testl $0x8080, %edx 
.46597: cmovel %ecx, %edx 
.46600: leaq 2(%rax), %rcx 
.46604: cmoveq %rcx, %rax 
.46608: movl %edx, %esi 
.46610: addb %dl, %sil 
.46613: sbbq $3, %rax 
.46617: subl %r13d, %eax 
.46620: cmpl %eax, .148300(%rip) 
.46626: jge .44558 
.46632: movl %eax, .148300(%rip) 
.46638: jmp .44558 
.46648: movl 0x34(%rbx), %edi 
.46651: callq .43264 
.46656: cmpl .148304(%rip), %eax 
.46662: jle .44545 
.46668: movl %eax, .148304(%rip) 
.46674: jmp .44545 
.46688: movq %r13, %rdi 
.46691: callq .88848 
.46696: movq %rax, %r15 
.46699: jmp .45216 
.46704: testl %r13d, %r13d 
.46707: sete %dl 
.46710: cmpl $6, %r13d 
.46714: je .46724 
.46716: testb %dl, %dl 
.46718: je .44304 
.46724: cmpl $5, .148216(%rip) 
.46731: je .47248 
.46737: cmpb $0, .148368(%rip) 
.46744: jne .44304 
.46750: cmpb $0, .148221(%rip) 
.46757: jne .44304 
.46763: testb %al, %al 
.46765: jne .44304 
.46771: cmpb $0, .148128(%rip) 
.46778: je .46896 
.46780: testb %dl, %dl 
.46782: jne .44304 
.46788: jmp .44163 
.46800: xorl %edx, %edx 
.46802: jmp .45965 
.46816: orq $0, -8(%rsp, %rcx) 
.46822: jmp .46074 
.46832: callq .18272 
.46837: cmpl $2, (%rax) 
.46840: je .43810 
.46846: movl $5, %edx 
.46851: leaq .104497(%rip), %rsi 
.46858: xorl %edi, %edi 
.46860: callq .18592 
.46865: movq %r14, %rdx 
.46868: movl $1, %edi 
.46873: xorl %r14d, %r14d 
.46876: movq %rax, %rsi 
.46879: callq .30704 
.46884: jmp .44019 
.46896: xorl %r14d, %r14d 
.46899: jmp .44000 
.46912: movl (%r13), %ecx 
.46916: shrl $0x1f, %eax 
.46919: movzbl -0x390(%rbp), %edx 
.46926: leal -0x16(%rcx), %esi 
.46929: andl $0xffffffef, %esi 
.46932: je .46939 
.46934: cmpl $0x5f, %ecx 
.46937: jne .46950 
.46939: movq 0x18(%rbx), %rcx 
.46943: movq %rcx, .144104(%rip) 
.46950: movl $1, %ecx 
.46955: testb %dl, %dl 
.46957: jne .46027 
.46963: movzbl .148324(%rip), %edx 
.46970: xorl %ecx, %ecx 
.46972: jmp .46027 
.46984: movl $5, %edx 
.46989: leaq .104514(%rip), %rsi 
.46996: xorl %edi, %edi 
.46998: callq .18592 
.47003: movzbl -0x384(%rbp), %edi 
.47010: movq %r14, %rdx 
.47013: movq %rax, %rsi 
.47016: callq .30704 
.47021: movq 8(%rbx), %r13 
.47025: testq %r13, %r13 
.47028: jne .45112 
.47034: xorl %r15d, %r15d 
.47037: jmp .45267 
.47048: cmpb $0, .148242(%rip) 
.47055: je .44096 
.47061: movl $0x13, %edi 
.47066: movb %r8b, -0x390(%rbp) 
.47073: callq .27456 
.47078: movzbl -0x390(%rbp), %r8d 
.47086: testb %al, %al 
.47088: jne .44304 
.47094: movl $0x12, %edi 
.47099: callq .27456 
.47104: movzbl -0x390(%rbp), %r8d 
.47112: testb %al, %al 
.47114: jne .44304 
.47120: movl $0x14, %edi 
.47125: callq .27456 
.47130: movzbl -0x390(%rbp), %r8d 
.47138: testb %al, %al 
.47140: jne .44304 
.47146: jmp .44096 
.47152: movl %r15d, %edi 
.47155: callq .68976 
.47160: movq %rax, %rdi 
.47163: testq %rax, %rax 
.47166: je .46529 
.47172: xorl %esi, %esi 
.47174: callq .71376 
.47179: movl $0, %edx 
.47184: testl %eax, %eax 
.47186: cmovsl %edx, %eax 
.47189: jmp .46620 
.47200: movq 8(%rbx), %rdi 
.47204: callq .28704 
.47209: testb %al, %al 
.47211: je .45241 
.47217: movl $0xffffffff, 0xc4(%rbx) 
.47227: jmp .45241 
.47232: movl $0x5f, (%r13) 
.47240: xorl %eax, %eax 
.47242: jmp .46950 
.47248: movzbl (%r12), %edx 
.47253: cmpb $0x2f, %dl 
.47256: jne .44321 
.47262: leaq 0x18(%rbx), %r15 
.47266: movq %r12, %r14 
.47269: jmp .44841 
.47274: hlt 
