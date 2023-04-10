.19872: hlt 
.37090: movzbl 0xb8(%r12), %edx 
.37099: cmpb $0, .148220(%rip) 
.37106: jne .37872 
.37112: leaq 0x4d0(%rsp), %rbp 
.37120: movq %rbp, %rbx 
.37123: cmpb $0, .148268(%rip) 
.37130: je .37245 
.37132: leaq .104418(%rip), %r14 
.37139: testb %dl, %dl 
.37141: jne .39184 
.37147: movl .148316(%rip), %r13d 
.37154: xorl %esi, %esi 
.37156: movq %r14, %rdi 
.37159: callq .71376 
.37164: subl %eax, %r13d 
.37167: movl %r13d, %eax 
.37170: testl %r13d, %r13d 
.37173: jle .37213 
.37175: subl $1, %eax 
.37178: movq %rax, %rdx 
.37181: leaq 1(%rbx, %rax), %rcx 
.37186: movq %rbx, %rax 
.37189: nopl (%rax) 
.37192: addq $1, %rax 
.37196: movb $0x20, -1(%rax) 
.37200: cmpq %rcx, %rax 
.37203: jne .37192 
.37205: movslq %edx, %rax 
.37208: leaq 1(%rbx, %rax), %rbx 
.37213: movzbl (%r14), %eax 
.37217: addq $1, %r14 
.37221: addq $1, %rbx 
.37225: movb %al, -1(%rbx) 
.37228: testb %al, %al 
.37230: jne .37213 
.37232: movb $0x20, -1(%rbx) 
.37236: movzbl 0xb8(%r12), %edx 
.37245: leaq .104418(%rip), %rax 
.37252: testb %dl, %dl 
.37254: jne .38528 
.37260: subq $8, %rsp 
.37264: movq %rbx, %rdi 
.37267: movl .148312(%rip), %r9d 
.37274: leaq .104447(%rip), %rcx 
.37281: pushq %rax 
.37282: movq $-1, %rdx 
.37289: movl $1, %esi 
.37294: xorl %eax, %eax 
.37296: leaq 0xc4(%rsp), %r8 
.37304: callq .19856 
.37309: movq %rbx, %rdi 
.37312: callq .18624 
.37317: popq %r8 
.37319: popq %r9 
.37321: addq %rax, %rbx 
.37324: cmpb $0, .148248(%rip) 
.37331: jne .38560 
.37337: cmpb $0, .143393(%rip) 
.37344: jne .37376 
.37346: cmpb $0, .143392(%rip) 
.37353: jne .37376 
.37355: cmpb $0, .148270(%rip) 
.37362: je .38800 
.37368: nopl (%rax, %rax) 
.37376: movq .144008(%rip), %rsi 
.37383: movq %rbp, %rdi 
.37386: subq %rbp, %rbx 
.37389: callq .19024 
.37394: addq %rbx, .147960(%rip) 
.37401: cmpb $0, .143393(%rip) 
.37408: jne .38608 
.37414: cmpb $0, .143392(%rip) 
.37421: jne .38646 
.37427: cmpb $0, .148270(%rip) 
.37434: jne .38697 
.37440: cmpb $0, .148325(%rip) 
.37447: movq %rbp, %rbx 
.37450: jne .38738 
.37456: cmpb $0, 0xb8(%r12) 
.37465: je .38016 
.37471: movl 0x30(%r12), %eax 
.37476: andl $0xb000, %eax 
.37481: cmpl $0x2000, %eax 
.37486: je .38992 
.37492: movq 0x48(%r12), %rdi 
.37497: movq .143384(%rip), %r8 
.37504: leaq 0xe0(%rsp), %rsi 
.37512: movl $1, %ecx 
.37517: movl .148252(%rip), %edx 
.37523: callq .65440 
.37528: movq %rax, %r14 
.37531: movl .148284(%rip), %r13d 
.37538: xorl %esi, %esi 
.37540: movq %r14, %rdi 
.37543: callq .71376 
.37548: subl %eax, %r13d 
.37551: movl %r13d, %eax 
.37554: testl %r13d, %r13d 
.37557: jle .37597 
.37559: subl $1, %eax 
.37562: movq %rax, %rdx 
.37565: leaq 1(%rbx, %rax), %rcx 
.37570: movq %rbx, %rax 
.37573: nopl (%rax) 
.37576: addq $1, %rax 
.37580: movb $0x20, -1(%rax) 
.37584: cmpq %rcx, %rax 
.37587: jne .37576 
.37589: movslq %edx, %rax 
.37592: leaq 1(%rbx, %rax), %rbx 
.37597: movzbl (%r14), %eax 
.37601: addq $1, %r14 
.37605: addq $1, %rbx 
.37609: movb %al, -1(%rbx) 
.37612: testb %al, %al 
.37614: jne .37597 
.37616: movb $0x20, -1(%rbx) 
.37620: movb $1, (%rbx) 
.37623: leaq .104418(%rip), %r13 
.37630: cmpb $0, 0xb8(%r12) 
.37639: jne .38312 
.37645: movl .143380(%rip), %r8d 
.37652: testl %r8d, %r8d 
.37655: js .39280 
.37661: movq %r13, %r9 
.37664: leaq .104463(%rip), %rcx 
.37671: movq %rbx, %rdi 
.37674: xorl %eax, %eax 
.37676: movq $-1, %rdx 
.37683: movl $1, %esi 
.37688: callq .19856 
.37693: movq %rbx, %rdi 
.37696: callq .18624 
.37701: leaq (%rbx, %rax), %r13 
.37705: movq .144008(%rip), %rsi 
.37712: movq %rbp, %rdi 
.37715: subq %rbp, %r13 
.37718: callq .19024 
.37723: movq %r13, %rcx 
.37726: xorl %esi, %esi 
.37728: movq %r12, %rdi 
.37731: leaq .147872(%rip), %rdx 
.37738: addq %r13, .147960(%rip) 
.37745: callq .35424 
.37750: movl 0xa8(%r12), %edx 
.37758: movq %rax, %rbp 
.37761: cmpl $6, %edx 
.37764: je .38200 
.37770: movl .148244(%rip), %eax 
.37776: testl %eax, %eax 
.37778: jne .38768 
.37784: movq 0x1318(%rsp), %rax 
.37792: xorq %fs:0x28, %rax 
.37801: jne .39568 
.37807: addq $0x1328, %rsp 
.37814: popq %rbx 
.37815: popq %rbp 
.37816: popq %r12 
.37818: popq %r13 
.37820: popq %r14 
.37822: popq %r15 
.37824: ret 
.37825: nopl (%rax) 
.37832: testl %eax, %eax 
.37834: jne .38192 
.37840: movq 0x78(%r12), %rax 
.37845: movq 0x70(%r12), %rdx 
.37850: movq %rax, 0x28(%rsp) 
.37855: movq %rdx, 0x20(%rsp) 
.37860: jmp .37090 
.37872: leaq .104418(%rip), %r9 
.37879: testb %dl, %dl 
.37881: je .37897 
.37883: movq 0x20(%r12), %rdi 
.37888: testq %rdi, %rdi 
.37891: jne .38880 
.37897: leaq 0x4d0(%rsp), %rbp 
.37905: movl .148320(%rip), %r8d 
.37912: movl $0xe3b, %edx 
.37917: xorl %eax, %eax 
.37919: leaq .104463(%rip), %rcx 
.37926: movl $1, %esi 
.37931: movq %rbp, %rdi 
.37934: movq %rbp, %rbx 
.37937: callq .19856 
.37942: movl (%rbx), %eax 
.37944: addq $4, %rbx 
.37948: leal -0x1010101(%rax), %edx 
.37954: notl %eax 
.37956: andl %eax, %edx 
.37958: andl $0x80808080, %edx 
.37964: je .37942 
.37966: movl %edx, %eax 
.37968: shrl $0x10, %eax 
.37971: testl $0x8080, %edx 
.37977: cmovel %eax, %edx 
.37980: leaq 2(%rbx), %rax 
.37984: cmoveq %rax, %rbx 
.37988: movl %edx, %eax 
.37990: addb %dl, %al 
.37992: movzbl 0xb8(%r12), %edx 
.38001: sbbq $3, %rbx 
.38005: jmp .37123 
.38016: leaq .104418(%rip), %r14 
.38023: jmp .37531 
.38192: jmp .19872 
.38200: cmpq $0, 8(%r12) 
.38206: je .37784 
.38212: movq .144008(%rip), %rcx 
.38219: movl $4, %edx 
.38224: movl $1, %esi 
.38229: leaq .104468(%rip), %rdi 
.38236: callq .19408 
.38241: xorl %edx, %edx 
.38243: leaq 4(%r13, %rbp), %rcx 
.38248: movq %r12, %rdi 
.38251: movl $1, %esi 
.38256: addq $4, .147960(%rip) 
.38264: callq .35424 
.38269: movl .148244(%rip), %edx 
.38275: testl %edx, %edx 
.38277: je .37784 
.38283: movl 0xac(%r12), %esi 
.38291: xorl %edx, %edx 
.38293: movl $1, %edi 
.38298: callq .31536 
.38303: jmp .37784 
.38312: leaq 0x30(%rsp), %r13 
.38317: movq .148136(%rip), %rdi 
.38324: leaq 0x20(%rsp), %rsi 
.38329: movq %r13, %rdx 
.38332: callq .94256 
.38337: testq %rax, %rax 
.38340: je .38496 
.38346: movq .148336(%rip), %rdx 
.38353: movq 0x20(%rsp), %rcx 
.38358: movq .148344(%rip), %rsi 
.38365: movq 0x28(%rsp), %r9 
.38370: cmpq %rcx, %rdx 
.38373: jl .39440 
.38379: jg .38904 
.38385: movl %esi, %edi 
.38387: movl %r9d, %eax 
.38390: cmpl %r9d, %esi 
.38393: js .39440 
.38399: subq $0xf0c2ac, %rdx 
.38406: cmpq %rdx, %rcx 
.38409: jg .38965 
.38415: xorl %eax, %eax 
.38417: cmpb $0, .144328(%rip) 
.38424: movq .148136(%rip), %r8 
.38431: je .39424 
.38437: leaq (%rax, %rax), %rdx 
.38441: addq %rdx, %rax 
.38444: movslq 0x40(%rsp), %rdx 
.38449: leaq (%rdx, %rax, 4), %rdx 
.38453: leaq .144352(%rip), %rax 
.38460: shlq $7, %rdx 
.38464: addq %rax, %rdx 
.38467: movq %r13, %rcx 
.38470: movl $0x3e9, %esi 
.38475: movq %rbx, %rdi 
.38478: callq .78464 
.38483: testq %rax, %rax 
.38486: je .38496 
.38488: addq %rax, %rbx 
.38491: jmp .38505 
.38496: cmpb $0, (%rbx) 
.38499: jne .39228 
.38505: movl $0x20, %ecx 
.38510: leaq 1(%rbx), %r13 
.38514: movw %cx, (%rbx) 
.38517: jmp .37705 
.38528: movq 0x28(%r12), %rdi 
.38533: leaq 0xe0(%rsp), %rsi 
.38541: callq .69568 
.38546: jmp .37260 
.38560: movq .144008(%rip), %rcx 
.38567: movl $2, %edx 
.38572: movl $1, %esi 
.38577: leaq .104455(%rip), %rdi 
.38584: callq .19408 
.38589: addq $2, .147960(%rip) 
.38597: jmp .37337 
.38608: movzbl 0xb8(%r12), %edx 
.38617: movl 0x34(%r12), %edi 
.38622: movl .148304(%rip), %esi 
.38628: callq .30592 
.38633: cmpb $0, .143392(%rip) 
.38640: je .37427 
.38646: cmpb $0, 0xb8(%r12) 
.38655: movl .148300(%rip), %edx 
.38661: leaq .104418(%rip), %rdi 
.38668: movl 0x38(%r12), %esi 
.38673: jne .38824 
.38679: callq .30400 
.38684: cmpb $0, .148270(%rip) 
.38691: je .37440 
.38697: movl 0x34(%r12), %edi 
.38702: movl .148296(%rip), %esi 
.38708: movq %rbp, %rbx 
.38711: movzbl 0xb8(%r12), %edx 
.38720: callq .30592 
.38725: cmpb $0, .148325(%rip) 
.38732: je .37456 
.38738: movq 0xb0(%r12), %rdi 
.38746: movl .148308(%rip), %edx 
.38752: xorl %esi, %esi 
.38754: callq .30400 
.38759: jmp .37456 
.38768: movzbl 0xb8(%r12), %edi 
.38777: movl 0x30(%r12), %esi 
.38782: callq .31536 
.38787: jmp .37784 
.38800: cmpb $0, .148325(%rip) 
.38807: je .37456 
.38813: jmp .37376 
.38824: xorl %edi, %edi 
.38826: cmpb $0, .148269(%rip) 
.38833: jne .38679 
.38839: movl %esi, %edi 
.38841: movq %rsi, 8(%rsp) 
.38846: movl %edx, 4(%rsp) 
.38850: callq .68976 
.38855: movq 8(%rsp), %rsi 
.38860: movl 4(%rsp), %edx 
.38864: movq %rax, %rdi 
.38867: jmp .38679 
.38880: leaq 0xe0(%rsp), %rsi 
.38888: callq .69568 
.38893: movq %rax, %r9 
.38896: jmp .37897 
.38904: leaq -0xf0c2ac(%rdx), %rdi 
.38911: cmpq %rcx, %rdi 
.38914: jl .39558 
.38920: xorl %eax, %eax 
.38922: cmpq %rcx, %rdi 
.38925: jg .38417 
.38931: cmpl %r9d, %esi 
.38934: jns .38417 
.38940: cmpq %rdx, %rcx 
.38943: jl .39558 
.38949: movl $0, %eax 
.38954: jg .38417 
.38960: movl %r9d, %eax 
.38963: movl %esi, %edi 
.38965: subl %edi, %eax 
.38967: shrl $0x1f, %eax 
.38970: jmp .38417 
.38992: movl .148292(%rip), %edx 
.38998: movl .148288(%rip), %eax 
.39004: leaq 0xe0(%rsp), %rsi 
.39012: movl .148284(%rip), %r13d 
.39019: leal 2(%rdx, %rax), %eax 
.39023: subl %eax, %r13d 
.39026: movq 0x40(%r12), %rax 
.39031: movzbl %al, %edx 
.39034: shrq $0xc, %rax 
.39038: movq %rax, %rdi 
.39041: xorb %dil, %dil 
.39044: orl %edx, %edi 
.39046: callq .69568 
.39051: movl .148288(%rip), %r15d 
.39058: leaq 0xc0(%rsp), %rsi 
.39066: movq %rax, %r14 
.39069: movq 0x40(%r12), %rax 
.39074: movq %rax, %rdi 
.39077: shrq $0x20, %rax 
.39081: shrq $8, %rdi 
.39085: movl %edi, %edx 
.39087: movq %rax, %rdi 
.39090: andl $0xfff, %edx 
.39096: andl $0xfffff000, %edi 
.39102: orl %edx, %edi 
.39104: callq .69568 
.39109: pushq %r14 
.39111: testl %r13d, %r13d 
.39114: movl $0, %r8d 
.39120: pushq %r15 
.39122: cmovnsl %r13d, %r8d 
.39126: movq %rbx, %rdi 
.39129: movq %rax, %r9 
.39132: movl $1, %esi 
.39137: addl .148292(%rip), %r8d 
.39144: movq $-1, %rdx 
.39151: leaq .104458(%rip), %rcx 
.39158: xorl %eax, %eax 
.39160: callq .19856 
.39165: movslq .148284(%rip), %rax 
.39172: popq %rsi 
.39173: popq %rdi 
.39174: leaq 1(%rbx, %rax), %rbx 
.39179: jmp .37620 
.39184: movq 0x58(%r12), %rdi 
.39189: movq .148256(%rip), %r8 
.39196: leaq 0xe0(%rsp), %rsi 
.39204: movl $0x200, %ecx 
.39209: movl .148264(%rip), %edx 
.39215: callq .65440 
.39220: movq %rax, %r14 
.39223: jmp .37147 
.39228: cmpb $0, 0xb8(%r12) 
.39237: je .39573 
.39243: movq 0x20(%rsp), %rdi 
.39248: leaq 0xc0(%rsp), %rsi 
.39256: callq .69408 
.39261: movl .143380(%rip), %r8d 
.39268: movq %rax, %r13 
.39271: testl %r8d, %r8d 
.39274: jns .37661 
.39280: leaq 0x70(%rsp), %r14 
.39285: movq .148136(%rip), %rdi 
.39292: leaq 0x18(%rsp), %rsi 
.39297: movq $0, 0x18(%rsp) 
.39306: movq %r14, %rdx 
.39309: callq .94256 
.39314: testq %rax, %rax 
.39317: je .39382 
.39319: cmpb $0, .144328(%rip) 
.39326: movq .148136(%rip), %r8 
.39333: movq .143424(%rip), %rdx 
.39340: jne .39504 
.39346: leaq 0xe0(%rsp), %r15 
.39354: xorl %r9d, %r9d 
.39357: movq %r14, %rcx 
.39360: movl $0x3e9, %esi 
.39365: movq %r15, %rdi 
.39368: callq .78464 
.39373: testq %rax, %rax 
.39376: jne .39531 
.39382: movl .143380(%rip), %r8d 
.39389: testl %r8d, %r8d 
.39392: jns .37661 
.39398: movl $0, .143380(%rip) 
.39408: xorl %r8d, %r8d 
.39411: jmp .37661 
.39424: leaq .143424(%rip), %rdx 
.39431: movq (%rdx, %rax, 8), %rdx 
.39435: jmp .38467 
.39440: leaq .148336(%rip), %rdi 
.39447: callq .60128 
.39452: movq 0x20(%rsp), %rcx 
.39457: movq 0x28(%rsp), %r9 
.39462: movq .148336(%rip), %rdx 
.39469: movq .148344(%rip), %rsi 
.39476: leaq -0xf0c2ac(%rdx), %rdi 
.39483: cmpq %rcx, %rdi 
.39486: jge .38920 
.39492: jmp .38940 
.39504: movslq 0x80(%rsp), %rdx 
.39512: leaq .144352(%rip), %rax 
.39519: shlq $7, %rdx 
.39523: addq %rax, %rdx 
.39526: jmp .39346 
.39531: xorl %edx, %edx 
.39533: movq %rax, %rsi 
.39536: movq %r15, %rdi 
.39539: callq .70832 
.39544: movl %eax, .143380(%rip) 
.39550: movl %eax, %r8d 
.39553: jmp .39389 
.39558: movl $1, %eax 
.39563: jmp .38417 
.39568: hlt 
.39573: leaq .104418(%rip), %r13 
.39580: jmp .37645 
