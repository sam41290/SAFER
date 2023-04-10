.18768: endbr64 
.18772: bnd jmpq *.142744(%rip) 
.20346: addb %al, -0x1977f040(%rbp) 
.20352: orb %al, (%rax) 
.20354: addb %cl, -0x68(%rax) 
.20357: leaq .117056(%rip), %rdx 
.20361: jns .20364 
.20363: addb %dh, (%rcx) 
.20364: xorl %edi, %edi 
.20365: decl 0x2ae88234(%rbx) 
.20366: movl (%rdx, %rax, 4), %esi 
.20369: callq .84160 
.20371: stc 
.20372: addb %al, (%rax) 
.20374: leaq .104809(%rip), %rdi 
.20381: movq $0x50, .148144(%rip) 
.20392: callq .18192 
.20397: movq %rax, %r13 
.20400: testq %rax, %rax 
.20403: je .20414 
.20405: cmpb $0, (%rax) 
.20408: jne .22685 
.20414: leaq 0x20(%rsp), %r13 
.20419: xorl %eax, %eax 
.20421: movl $0x5413, %esi 
.20426: movl $1, %edi 
.20431: movq %r13, %rdx 
.20434: callq .18928 
.20439: cmpl $-1, %eax 
.20442: je .20458 
.20444: movzwl 0x22(%rsp), %eax 
.20449: testw %ax, %ax 
.20452: jne .22621 
.20458: leaq .104817(%rip), %rdi 
.20465: callq .18192 
.20470: movq $8, .148160(%rip) 
.20481: movq %rax, %r14 
.20484: testq %rax, %rax 
.20487: je .20527 
.20489: xorl %r8d, %r8d 
.20492: xorl %edx, %edx 
.20494: xorl %esi, %esi 
.20496: movq %r13, %rcx 
.20499: movq %rax, %rdi 
.20502: callq .89520 
.20506: addb %al, 0x2f850fc0(%rbp) 
.20507: testl %eax, %eax 
.20509: jne .23890 
.20512: orl $0x8b480000, %eax 
.20515: movq 0x20(%rsp), %rax 
.20517: andb $0x20, %al 
.20518: andb $0x20, %al 
.20520: movq %rax, .148160(%rip) 
.20527: movb $0, 4(%rsp) 
.20532: xorl %r14d, %r14d 
.20535: xorl %r15d, %r15d 
.20538: leaq .98648(%rip), %rbx 
.20545: movq %r13, %r8 
.20548: leaq .140032(%rip), %rcx 
.20555: movq %rbp, %rsi 
.20558: movl %r12d, %edi 
.20561: leaq .113896(%rip), %rdx 
.20568: movl $0xffffffff, 0x20(%rsp) 
.20576: callq .18672 
.20581: cmpl $-1, %eax 
.20584: je .20688 
.20586: addl $0x83, %eax 
.20589: addb %al, (%rax) 
.20591: cmpl $0x113, %eax 
.20596: ja .25751 
.20602: movslq (%rbx, %rax, 4), %rax 
.20606: addq %rbx, %rax 
.20609: jmpq *%rax 
.20658: movl $1, %r14d 
.20664: jmp .20545 
.20665: xchgl %eax, %esi 
.20666: movb $1, .148269(%rip) 
.20667: addl $0x1f26c, %eax 
.20672: addl %eax, %edi 
.20673: movl $0, .148280(%rip) 
.20674: addl $0x1f26d, %eax 
.20679: addb %al, (%rax) 
.20681: addb %al, (%rax) 
.20683: jmp .20545 
.20688: cmpq $0, .148256(%rip) 
.20696: je .23942 
.20702: movq .148144(%rip), %rax 
.20709: movl $3, %ecx 
.20712: addb %al, (%rax) 
.20714: xorl %edx, %edx 
.20716: divq %rcx 
.20719: testq %rdx, %rdx 
.20722: setne %dl 
.20724: ret 
.20725: xorl %edi, %edi 
.20727: movzbl %dl, %edx 
.20730: addq %rdx, %rax 
.20733: movq %rax, .147968(%rip) 
.20740: callq .84128 
.20745: movl .148280(%rip), %edx 
.20751: movl %eax, %ebx 
.20753: cmpl $4, %edx 
.20756: je .22753 
.20762: cmpl $1, %edx 
.20765: je .22753 
.20771: cmpq $0, .148144(%rip) 
.20779: jne .20791 
.20781: xorl %eax, %eax 
.20783: testl %edx, %edx 
.20785: jne .22755 
.20791: movl %ebx, %eax 
.20793: andl $0xfffffffd, %eax 
.20796: subl $1, %eax 
.20799: sete %al 
.20802: cmpl $6, %ebx 
.20805: sete %dl 
.20808: orl %edx, %eax 
.20810: movzbl %al, %eax 
.20813: jmp .22755 
.20818: movq .144024(%rip), %r15 
.20825: jmp .20545 
.20830: movq .143856(%rip), %r9 
.20837: movq .144024(%rip), %rsi 
.20844: movl $4, %r8d 
.20850: leaq .100048(%rip), %rcx 
.20857: leaq .139840(%rip), %rdx 
.20864: leaq .104879(%rip), %rdi 
.20867: subb %cl, 1(%rax) 
.20870: addb %ch, %al 
.20871: callq .55216 
.20872: andb $0x86, %al 
.20874: addb %al, (%rax) 
.20876: movq %rax, %r8 
.20879: leaq .100048(%rip), %rax 
.20886: movl (%rax, %r8, 4), %eax 
.20890: movl %eax, .148276(%rip) 
.20896: jmp .20545 
.20901: movq .143856(%rip), %r9 
.20908: movq .144024(%rip), %rsi 
.20915: movl $4, %r8d 
.20921: leaq .100080(%rip), %rcx 
.20928: leaq .139904(%rip), %rdx 
.20935: leaq .104872(%rip), %rdi 
.20942: callq .55216 
.20947: movb $1, 4(%rsp) 
.20952: movq %rax, %r8 
.20955: leaq .100080(%rip), %rax 
.20962: movl (%rax, %r8, 4), %eax 
.20966: movl %eax, .148272(%rip) 
.20972: jmp .20545 
.20977: movl $0x90, .148264(%rip) 
.20979: subl $0x900001f1, %eax 
.20984: addb %al, (%rax) 
.20986: addb %al, %bh 
.20987: movl $0x90, .148252(%rip) 
.20988: addl $0x1f117, %eax 
.20993: nop 
.20994: addb %al, (%rax) 
.20996: addb %cl, -0x39(%rax) 
.20997: movq $1, .148256(%rip) 
.20999: addl $0x1f110, %eax 
.21004: addl %eax, (%rax) 
.21006: addb %al, (%rax) 
.21008: movq $1, .143384(%rip) 
.21019: jmp .20545 
.21024: movb $0, .148184(%rip) 
.21031: jmp .20545 
.21036: movq .143856(%rip), %r9 
.21043: movq .144024(%rip), %rsi 
.21050: movl $4, %r8d 
.21056: leaq .117056(%rip), %rcx 
.21063: leaq .141824(%rip), %rdx 
.21070: leaq .104933(%rip), %rdi 
.21077: callq .55216 
.21082: xorl %edi, %edi 
.21084: movq %rax, %r8 
.21087: leaq .117056(%rip), %rax 
.21094: movl (%rax, %r8, 4), %esi 
.21098: callq .84160 
.21103: jmp .20545 
.21108: movq .143856(%rip), %r9 
.21115: movq .144024(%rip), %rsi 
.21122: movl $4, %r8d 
.21127: addb %cl, -0x73(%rax) 
.21128: leaq .100144(%rip), %rcx 
.21130: orl $0x134a1, %eax 
.21135: leaq .141664(%rip), %rdx 
.21142: leaq .104915(%rip), %rdi 
.21149: callq .55216 
.21154: movq %rax, %r8 
.21157: leaq .100144(%rip), %rax 
.21164: movl (%rax, %r8, 4), %eax 
.21168: movl %eax, .148244(%rip) 
.21174: jmp .20545 
.21179: movq .144024(%rip), %rsi 
.21186: testq %rsi, %rsi 
.21189: je .23750 
.21195: movq .143856(%rip), %r9 
.21202: movl $4, %r8d 
.21208: leaq .139744(%rip), %rdx 
.21215: leaq .100000(%rip), %rcx 
.21222: leaq .104903(%rip), %rdi 
.21229: callq .55216 
.21234: movq %rax, %r8 
.21237: leaq .100000(%rip), %rax 
.21244: movl (%rax, %r8, 4), %edx 
.21248: cmpl $1, %edx 
.21251: je .23750 
.21256: addb %dh, (%rcx) 
.21257: xorl %eax, %eax 
.21258: rolb $0xb7, -0x7af0fd06(%rbx) 
.21259: cmpl $2, %edx 
.21262: jne .23755 
.21265: orl %eax, (%rax) 
.21267: addb %bh, 1(%rdi) 
.21268: movl $1, %edi 
.21273: callq .18368 
.21278: testl %eax, %eax 
.21280: setne %al 
.21283: movzbl %al, %eax 
.21286: jmp .23755 
.21291: movl $0x10, %edi 
.21296: callq .88256 
.21301: movq .144024(%rip), %rdx 
.21308: movq %rdx, (%rax) 
.21311: movq .148192(%rip), %rdx 
.21318: movq %rax, .148192(%rip) 
.21325: movq %rdx, 8(%rax) 
.21329: jmp .20545 
.21334: movb $1, .148212(%rip) 
.21341: jmp .20545 
.21346: movl $0, .148280(%rip) 
.21356: leaq .104765(%rip), %r15 
.21363: jmp .20545 
.21368: movq .143856(%rip), %r9 
.21375: movq .144024(%rip), %rsi 
.21376: movl .144024(%rip), %esi 
.21382: movl $4, %r8d 
.21388: leaq .100112(%rip), %rcx 
.21395: leaq .139968(%rip), %rdx 
.21402: leaq .104886(%rip), %rdi 
.21403: leal .104886(%rip), %edi 
.21409: callq .55216 
.21414: movq %rax, %r8 
.21417: leaq .100112(%rip), %rax 
.21424: movl (%rax, %r8, 4), %eax 
.21428: movl %eax, .148280(%rip) 
.21434: jmp .20545 
.21439: movl $2, .148244(%rip) 
.21449: jmp .20545 
.21454: movl $4, .148216(%rip) 
.21464: jmp .20545 
.21469: movq .144024(%rip), %rsi 
.21476: testq %rsi, %rsi 
.21479: je .23727 
.21484: addb %cl, 0xd(%rbx, %rcx, 4) 
.21485: movq .143856(%rip), %r9 
.21488: cld 
.21489: fldl (%rcx) 
.21491: addb %al, -0x48(%rcx) 
.21492: movl $4, %r8d 
.21494: addb $0, %al 
.21496: addb %al, (%rax) 
.21498: leaq .100000(%rip), %rcx 
.21505: leaq .139744(%rip), %rdx 
.21508: fmul %st(5) 
.21510: addl %eax, (%rax) 
.21512: leaq .104895(%rip), %rdi 
.21519: callq .55216 
.21520: pushfq 
.21521: addl $0, (%rax) 
.21524: movq %rax, %r8 
.21527: leaq .100000(%rip), %rax 
.21534: movl (%rax, %r8, 4), %eax 
.21535: movl (%rax, %rax, 4), %eax 
.21538: cmpl $1, %eax 
.21541: je .23727 
.21547: cmpl $2, %eax 
.21550: je .23709 
.21556: movb $0, .148242(%rip) 
.21563: jmp .20545 
.21568: movq .144024(%rip), %rdi 
.21572: fiadds (%rcx) 
.21574: addb %cl, -0x73(%rax) 
.21575: leaq .148256(%rip), %rdx 
.21577: adcl $0x1eed2, %eax 
.21582: leaq .148264(%rip), %rsi 
.21584: xorl $0x1eed3, %eax 
.21589: callq .68064 
.21594: testl %eax, %eax 
.21596: jne .26484 
.21602: movl .148264(%rip), %eax 
.21608: movl %eax, .148252(%rip) 
.21614: movq .148256(%rip), %rax 
.21621: movq %rax, .143384(%rip) 
.21628: jmp .20545 
.21633: movl $3, .148272(%rip) 
.21643: movb $1, 4(%rsp) 
.21648: jmp .20545 
.21653: movl $2, .148276(%rip) 
.21663: jmp .20545 
.21668: movl $4, .148272(%rip) 
.21678: movb $1, 4(%rsp) 
.21683: jmp .20545 
.21688: movb $1, .148268(%rip) 
.21695: jmp .20545 
.21700: movl $3, .148280(%rip) 
.21710: jmp .20545 
.21715: movq .144024(%rip), %rdi 
.21717: cmpl $0x1ddbe, %eax 
.21722: callq .27568 
.21727: testb %al, %al 
.21729: jne .20545 
.21735: movq .144024(%rip), %rdi 
.21742: callq .86080 
.21744: sti 
.21745: addb %al, (%rax) 
.21747: movl $5, %edx 
.21752: leaq .104825(%rip), %rsi 
.21759: xorl %edi, %edi 
.21761: movq %rax, %rbx 
.21764: callq .18592 
.21769: movq %rbx, %r8 
.21772: xorl %esi, %esi 
.21774: movl $2, %edi 
.21779: movq %rax, %rcx 
.21782: leaq .104844(%rip), %rdx 
.21789: xorl %eax, %eax 
.21791: callq .19552 
.21796: movb $1, .148270(%rip) 
.21803: jmp .20545 
.21808: movb $1, .148271(%rip) 
.21815: jmp .20545 
.21820: movb $1, .148184(%rip) 
.21827: jmp .20545 
.21832: movl $1, .148244(%rip) 
.21842: jmp .20545 
.21847: movl $0, .148280(%rip) 
.21857: movb $0, .143392(%rip) 
.21864: jmp .20545 
.21869: movl $4, .148280(%rip) 
.21879: jmp .20545 
.21884: movb $1, .148220(%rip) 
.21891: jmp .20545 
.21896: movl $0xb0, .148264(%rip) 
.21906: movl $0xb0, .148252(%rip) 
.21914: addb %al, (%rax) 
.21916: movq $1, .148256(%rip) 
.21926: addb %cl, -0x39(%rax) 
.21927: movq $1, .143384(%rip) 
.21929: addl $0x1da66, %eax 
.21934: addl %eax, (%rax) 
.21936: addb %al, (%rax) 
.21938: jmp .20545 
.21943: movl $0, .148280(%rip) 
.21953: movb $0, .143393(%rip) 
.21960: jmp .20545 
.21965: cmpl $0, .148280(%rip) 
.21972: movl $2, .148208(%rip) 
.21982: movl $0xffffffff, .148272(%rip) 
.21992: je .25208 
.21998: movb $0, .148268(%rip) 
.22005: movb $0, .148242(%rip) 
.22012: movb $0, .148241(%rip) 
.22019: movb $1, 4(%rsp) 
.22024: jmp .20545 
.22029: movb $1, .148213(%rip) 
.22036: jmp .20545 
.22040: incl %edi 
.22041: movl $1, .148276(%rip) 
.22042: addl $0x1ed11, %eax 
.22047: addl %eax, (%rax) 
.22049: addb %al, (%rax) 
.22051: jmp .20545 
.22056: movl $7, %esi 
.22061: xorl %edi, %edi 
.22063: callq .84160 
.22068: jmp .20545 
.22073: movl $2, .148208(%rip) 
.22079: addb (%rax), %al 
.22081: addb %al, (%rax) 
.22083: jmp .20545 
.22088: movb $1, .148325(%rip) 
.22095: jmp .20545 
.22100: movl $1, .148272(%rip) 
.22110: movb $1, 4(%rsp) 
.22115: jmp .20545 
.22120: movl $0xffffffff, .148272(%rip) 
.22130: movb $1, 4(%rsp) 
.22135: jmp .20545 
.22140: movl $5, %edx 
.22145: leaq .104855(%rip), %rsi 
.22152: xorl %edi, %edi 
.22154: callq .18592 
.22159: movq .144024(%rip), %rdi 
.22166: orq $0xffffffffffffffff, %rcx 
.22170: xorl %esi, %esi 
.22172: pushq %rdx 
.22173: movq %rax, %r9 
.22175: rorl $0x57, 5(%rbp, %rcx, 4) 
.22176: leaq .104446(%rip), %r8 
.22180: addl %eax, (%r8) 
.22183: xorl %edx, %edx 
.22185: pushq $2 
.22187: callq .88944 
.22190: addl %eax, (%rax) 
.22192: popq %rcx 
.22193: popq %rsi 
.22194: movq %rax, .148160(%rip) 
.22201: jmp .20545 
.22206: movl $2, .148272(%rip) 
.22216: movb $1, 4(%rsp) 
.22221: jmp .20545 
.22226: movb $1, .148214(%rip) 
.22233: jmp .20545 
.22238: movl $5, %esi 
.22243: xorl %edi, %edi 
.22245: callq .84160 
.22250: jmp .20545 
.22255: xorl %esi, %esi 
.22257: xorl %edi, %edi 
.22259: callq .84160 
.22264: jmp .20545 
.22269: movl $5, .148216(%rip) 
.22279: jmp .20545 
.22284: movq .144024(%rip), %rdx 
.22291: movl $0x10, %edi 
.22296: movq %rdx, 8(%rsp) 
.22301: callq .88256 
.22306: movq 8(%rsp), %rdx 
.22311: movq %rdx, (%rax) 
.22314: movq .148200(%rip), %rdx 
.22321: movq %rdx, 8(%rax) 
.22325: movq %rax, .148200(%rip) 
.22332: jmp .20545 
.22337: movl $3, .148216(%rip) 
.22347: jmp .20545 
.22352: movb $0, .143392(%rip) 
.22359: jmp .20545 
.22364: movl $3, .148244(%rip) 
.22374: jmp .20545 
.22379: movb $1, .148248(%rip) 
.22386: jmp .20545 
.22391: movl $2, .148280(%rip) 
.22401: jmp .20545 
.22406: movl $0x10, %edi 
.22411: callq .88256 
.22416: movq .148200(%rip), %rdx 
.22423: movl $0x10, %edi 
.22428: leaq .104852(%rip), %rcx 
.22435: movq %rcx, (%rax) 
.22438: movq %rdx, 8(%rax) 
.22442: movq %rax, .148200(%rip) 
.22449: callq .88256 
.22454: movq .148200(%rip), %rdx 
.22461: leaq .104851(%rip), %rcx 
.22468: movq %rcx, (%rax) 
.22471: movq %rdx, 8(%rax) 
.22475: movq %rax, .148200(%rip) 
.22482: jmp .20545 
.22487: movl $1, .148208(%rip) 
.22497: jmp .20545 
.22502: cmpl $0, .148280(%rip) 
.22509: je .20545 
.22515: movl $1, .148280(%rip) 
.22525: jmp .20545 
.22530: movl .143840(%rip), %eax 
.22536: movq .143848(%rip), %rcx 
.22543: leaq .104758(%rip), %rsi 
.22550: cmpl $1, %eax 
.22553: je .22576 
.22555: cmpl $2, %eax 
.22558: leaq .104627(%rip), %rsi 
.22565: leaq .104626(%rip), %rax 
.22572: cmovneq %rax, %rsi 
.22576: pushq %rax 
.22577: movq .144008(%rip), %rdi 
.22584: xorl %eax, %eax 
.22586: leaq .104949(%rip), %r9 
.22593: pushq $0 
.22595: leaq .104965(%rip), %r8 
.22602: leaq .104747(%rip), %rdx 
.22609: callq .87888 
.22614: xorl %edi, %edi 
.22616: hlt 
.22621: movq %rax, .148144(%rip) 
.22628: jmp .20458 
.22685: movq %rax, %rdi 
.22688: callq .27568 
.22693: testb %al, %al 
.22695: jne .20414 
.22701: movq %r13, %rdi 
.22704: callq .86080 
.22709: xorl %edi, %edi 
.22711: movl $5, %edx 
.22716: leaq .113768(%rip), %rsi 
.22723: movq %rax, %r13 
.22726: callq .18592 
.22731: movq %r13, %rcx 
.22734: xorl %esi, %esi 
.22736: xorl %edi, %edi 
.22738: movq %rax, %rdx 
.22741: xorl %eax, %eax 
.22743: callq .19552 
.22748: jmp .20414 
.22753: xorl %eax, %eax 
.22755: xorl %edi, %edi 
.22757: movb %al, .148392(%rip) 
.22763: andb $1, .148392(%rip) 
.22770: callq .84064 
.22775: movq %rax, .148176(%rip) 
.22782: cmpl $7, %ebx 
.22785: je .25345 
.22791: movl .148244(%rip), %eax 
.22797: cmpl $1, %eax 
.22800: jbe .22863 
.22802: subl $2, %eax 
.22805: leaq .104999(%rip), %rdx 
.22812: leaq (%rax, %rdx), %rbx 
.22816: movzbl (%rdx, %rax), %eax 
.22820: testb %al, %al 
.22822: je .22863 
.22824: nopl (%rax, %rax) 
.22832: movq .148176(%rip), %rdi 
.22839: movsbl %al, %esi 
.22842: movl $1, %edx 
.22847: addq $1, %rbx 
.22851: callq .84192 
.22856: movzbl (%rbx), %eax 
.22859: testb %al, %al 
.22861: jne .22832 
.22863: xorl %edi, %edi 
.22865: callq .84064 
.22870: movl $1, %edx 
.22875: movl $0x3a, %esi 
.22880: movq %rax, %rdi 
.22883: movq %rax, .148168(%rip) 
.22890: callq .84192 
.22895: cmpb $0, .148248(%rip) 
.22902: je .22924 
.22904: cmpl $0, .148280(%rip) 
.22911: je .24049 
.22917: movb $0, .148248(%rip) 
.22924: movl .148276(%rip), %eax 
.22930: movl .148280(%rip), %edx 
.22936: subl $1, %eax 
.22939: cmpl $1, %eax 
.22942: ja .22955 
.22944: cmpb $0, 4(%rsp) 
.22949: je .24332 
.22955: testl %edx, %edx 
.22957: jne .23026 
.22959: testq %r15, %r15 
.22962: je .26092 
.22968: leaq .99987(%rip), %rbx 
.22975: jmp .22988 
.22984: addq $6, %r15 
.22988: movl $6, %edx 
.22993: movq %rbx, %rsi 
.22996: movq %r15, %rdi 
.22999: callq .18288 
.23004: testl %eax, %eax 
.23006: jne .25237 
.23012: movl $2, %edi 
.23017: callq .60240 
.23022: testb %al, %al 
.23024: jne .22984 
.23026: cmpb $0, .148242(%rip) 
.23033: movslq .144016(%rip), %rbx 
.23040: jne .24404 
.23046: cmpl $1, .148216(%rip) 
.23053: je .24355 
.23059: cmpb $0, .148214(%rip) 
.23066: je .23147 
.23068: leaq .27440(%rip), %r8 
.23075: leaq .26832(%rip), %rcx 
.23082: xorl %esi, %esi 
.23084: movl $0x1e, %edi 
.23089: leaq .26816(%rip), %rdx 
.23096: callq .62656 
.23101: movq %rax, .148424(%rip) 
.23108: testq %rax, %rax 
.23111: je .26479 
.23117: movq .143296(%rip), %r8 
.23124: movq .143328(%rip), %rcx 
.23131: xorl %edx, %edx 
.23133: xorl %esi, %esi 
.23135: leaq .147680(%rip), %rdi 
.23142: callq .92800 
.23147: leaq .105200(%rip), %rdi 
.23154: callq .18192 
.23159: movq %rax, %rdi 
.23162: callq .93520 
.23167: movq %rax, .148136(%rip) 
.23174: movl .148272(%rip), %eax 
.23180: subl $2, %eax 
.23183: andl $0xfffffffd, %eax 
.23186: je .23201 
.23188: cmpl $0, .148280(%rip) 
.23195: jne .24175 
.23201: movb $1, .148129(%rip) 
.23208: xorl %eax, %eax 
.23210: movb %al, .148128(%rip) 
.23216: andb $1, .148128(%rip) 
.23223: cmpb $0, .148248(%rip) 
.23230: jne .25058 
.23236: cmpb $0, .148241(%rip) 
.23243: jne .24904 
.23249: movl $0x4e20, %edi 
.23254: movl %r12d, %r14d 
.23257: movq $0x64, .148408(%rip) 
.23268: leaq .104446(%rip), %r15 
.23275: callq .88256 
.23280: subl %ebx, %r14d 
.23283: movq $0, .148400(%rip) 
.23294: movq %rax, .148416(%rip) 
.23301: callq .28528 
.23306: testl %r14d, %r14d 
.23309: jle .23805 
.23315: nopl (%rax, %rax) 
.23320: movq (%rbp, %rbx, 8), %rdi 
.23325: movq %r15, %rcx 
.23328: movl $1, %edx 
.23333: xorl %esi, %esi 
.23335: addq $1, %rbx 
.23339: callq .43472 
.23344: cmpl %ebx, %r12d 
.23347: jg .23320 
.23349: cmpq $0, .148400(%rip) 
.23357: jne .24808 
.23363: subl $1, %r14d 
.23367: jg .23422 
.23369: jmp .23851 
.23376: movzbl 0x10(%rbp), %edx 
.23380: movq 8(%rbp), %rsi 
.23384: callq .47296 
.23389: movq (%rbp), %rdi 
.23393: callq .18128 
.23398: movq 8(%rbp), %rdi 
.23402: callq .18128 
.23407: movq %rbp, %rdi 
.23410: callq .18128 
.23415: movb $1, .148152(%rip) 
.23422: movq .148352(%rip), %rbp 
.23429: testq %rbp, %rbp 
.23432: je .23596 
.23438: movq 0x18(%rbp), %rax 
.23442: movq .148424(%rip), %r8 
.23449: movq (%rbp), %rdi 
.23453: movq %rax, .148352(%rip) 
.23460: testq %r8, %r8 
.23463: je .23376 
.23465: testq %rdi, %rdi 
.23468: jne .23376 
.23470: movq .147704(%rip), %rax 
.23477: movq %rax, %rdx 
.23480: subq .147696(%rip), %rdx 
.23487: cmpq $0xf, %rdx 
.23491: jbe .26511 
.23497: leaq -0x10(%rax), %rdx 
.23501: movq %r8, %rdi 
.23504: movq %r13, %rsi 
.23507: movq %rdx, .147704(%rip) 
.23514: movq -0x10(%rax), %rdx 
.23518: movq -8(%rax), %rax 
.23522: movq %rdx, 0x20(%rsp) 
.23527: movq %rax, 0x28(%rsp) 
.23532: callq .64512 
.23537: movq %rax, %rdi 
.23540: testq %rax, %rax 
.23543: je .26542 
.23549: callq .18128 
.23554: movq (%rbp), %rdi 
.23558: callq .18128 
.23563: movq 8(%rbp), %rdi 
.23567: callq .18128 
.23572: movq %rbp, %rdi 
.23575: callq .18128 
.23580: movq .148352(%rip), %rbp 
.23587: testq %rbp, %rbp 
.23590: jne .23438 
.23596: cmpb $0, .148242(%rip) 
.23603: je .23618 
.23605: cmpb $0, .148240(%rip) 
.23612: jne .24067 
.23618: cmpb $0, .148248(%rip) 
.23625: jne .25121 
.23631: movq .148424(%rip), %rbp 
.23638: testq %rbp, %rbp 
.23641: je .23668 
.23643: movq %rbp, %rdi 
.23646: callq .61472 
.23651: testq %rax, %rax 
.23654: jne .26236 
.23660: movq %rbp, %rdi 
.23663: callq .63104 
.23668: movq 0x38(%rsp), %rbx 
.23673: xorq %fs:0x28, %rbx 
.23682: movl .147984(%rip), %eax 
.23688: jne .26267 
.23694: addq $0x48, %rsp 
.23698: popq %rbx 
.23699: popq %rbp 
.23700: popq %r12 
.23702: popq %r13 
.23704: popq %r14 
.23706: popq %r15 
.23708: ret 
.23709: movl $1, %edi 
.23714: callq .18368 
.23719: testl %eax, %eax 
.23721: je .21556 
.23727: movb $1, .148242(%rip) 
.23734: movq $0, .148160(%rip) 
.23745: jmp .20545 
.23750: movl $1, %eax 
.23755: movb %al, .148241(%rip) 
.23761: andb $1, .148241(%rip) 
.23768: jmp .20545 
.23805: cmpb $0, .148213(%rip) 
.23812: jne .24298 
.23818: movl $1, %edx 
.23823: xorl %esi, %esi 
.23825: leaq .105203(%rip), %rdi 
.23832: callq .28288 
.23837: cmpq $0, .148400(%rip) 
.23845: jne .24808 
.23851: movq .148352(%rip), %rbp 
.23858: testq %rbp, %rbp 
.23861: je .23596 
.23867: cmpq $0, 0x18(%rbp) 
.23872: jne .23438 
.23878: movb $0, .148152(%rip) 
.23885: jmp .23438 
.23890: movq %r14, %rdi 
.23893: callq .86080 
.23898: xorl %edi, %edi 
.23900: movl $5, %edx 
.23905: leaq .113832(%rip), %rsi 
.23912: movq %rax, %r14 
.23915: callq .18592 
.23920: movq %r14, %rcx 
.23923: xorl %esi, %esi 
.23925: xorl %edi, %edi 
.23927: movq %rax, %rdx 
.23930: xorl %eax, %eax 
.23932: callq .19552 
.23937: jmp .20527 
.23942: leaq .104985(%rip), %rdi 
.23949: callq .18192 
.23954: leaq .148256(%rip), %rdx 
.23961: leaq .148264(%rip), %rsi 
.23968: movq %rax, %rbx 
.23971: movq %rax, %rdi 
.23974: callq .68064 
.23979: testq %rbx, %rbx 
.23982: je .26128 
.23988: movl .148264(%rip), %eax 
.23994: movl %eax, .148252(%rip) 
.24000: movq .148256(%rip), %rax 
.24007: movq %rax, .143384(%rip) 
.24014: testb %r14b, %r14b 
.24017: je .20702 
.24023: movl $0, .148264(%rip) 
.24033: movq $0x400, .148256(%rip) 
.24044: jmp .20702 
.24049: cmpb $0, .148241(%rip) 
.24056: je .22959 
.24062: jmp .22917 
.24067: cmpq $2, .143456(%rip) 
.24075: jne .24095 
.24077: movq .143464(%rip), %rax 
.24084: cmpw $0x5b1b, (%rax) 
.24089: je .25761 
.24095: callq .32864 
.24100: movq .144008(%rip), %rdi 
.24107: callq .19760 
.24112: xorl %edi, %edi 
.24114: callq .32192 
.24119: movl .147988(%rip), %ebx 
.24125: testl %ebx, %ebx 
.24127: je .24151 
.24129: nopl (%rax) 
.24136: movl $0x13, %edi 
.24141: callq .18240 
.24146: subl $1, %ebx 
.24149: jne .24136 
.24151: movl .147992(%rip), %edi 
.24157: testl %edi, %edi 
.24159: je .23618 
.24165: callq .18240 
.24170: jmp .23618 
.24175: cmpb $0, .148325(%rip) 
.24182: jne .23201 
.24188: cmpb $0, .148268(%rip) 
.24195: jne .23201 
.24201: cmpb $0, .148214(%rip) 
.24208: movb $0, .148129(%rip) 
.24215: movl $1, %eax 
.24220: jne .23210 
.24226: cmpb $0, .148242(%rip) 
.24233: jne .23210 
.24239: cmpl $0, .148244(%rip) 
.24246: jne .23210 
.24252: movzbl .148212(%rip), %eax 
.24259: jmp .23210 
.24298: leaq .104446(%rip), %rcx 
.24305: movl $1, %edx 
.24310: movl $3, %esi 
.24315: leaq .105203(%rip), %rdi 
.24322: callq .43472 
.24327: jmp .23837 
.24332: testl %edx, %edx 
.24334: je .22959 
.24340: movl $4, .148272(%rip) 
.24350: jmp .23026 
.24355: cmpb $0, .148213(%rip) 
.24362: movl $2, %eax 
.24367: jne .24393 
.24369: cmpl $3, .148244(%rip) 
.24376: je .24393 
.24378: cmpl $1, .148280(%rip) 
.24385: sbbl %eax, %eax 
.24387: andl $0xfffffffe, %eax 
.24390: addl $4, %eax 
.24393: movl %eax, .148216(%rip) 
.24399: jmp .23059 
.24404: leaq .105143(%rip), %rdi 
.24411: callq .18192 
.24416: movq %rax, 0x18(%rsp) 
.24421: movq %rax, %rdi 
.24424: testq %rax, %rax 
.24427: je .25368 
.24433: cmpb $0, (%rax) 
.24436: je .25368 
.24442: movw $0x3f3f, 0x35(%rsp) 
.24449: movb $0, 0x37(%rsp) 
.24454: callq .88848 
.24459: movl %ebx, 4(%rsp) 
.24463: movq %rax, .148224(%rip) 
.24470: movq %rax, 0x20(%rsp) 
.24475: movq 0x18(%rsp), %rax 
.24480: movzbl (%rax), %edx 
.24483: cmpb $0x2a, %dl 
.24486: je .25873 
.24492: cmpb $0x3a, %dl 
.24495: je .25859 
.24501: testb %dl, %dl 
.24503: je .25796 
.24509: leaq 1(%rax), %rdx 
.24513: movq %rdx, 0x18(%rsp) 
.24518: movzbl (%rax), %edx 
.24521: movb %dl, 0x35(%rsp) 
.24525: cmpb $0, 1(%rax) 
.24529: je .25941 
.24535: leaq 2(%rax), %rdx 
.24539: movq %rdx, 0x18(%rsp) 
.24544: movzbl 1(%rax), %edx 
.24548: movb %dl, 0x36(%rsp) 
.24552: leaq 3(%rax), %rdx 
.24556: movq %rdx, 0x18(%rsp) 
.24561: cmpb $0x3d, 2(%rax) 
.24565: jne .25941 
.24571: xorl %ebx, %ebx 
.24573: leaq .104774(%rip), %rsi 
.24580: leaq 0x35(%rsp), %r15 
.24585: jmp .24612 
.24592: addq $1, %rbx 
.24596: leaq .141440(%rip), %rax 
.24603: movq (%rax, %rbx, 8), %rsi 
.24607: testq %rsi, %rsi 
.24610: je .24673 
.24612: movq %r15, %rdi 
.24615: callq .19072 
.24620: testl %eax, %eax 
.24622: jne .24592 
.24624: movslq %ebx, %rcx 
.24627: leaq .143456(%rip), %rax 
.24634: xorl %edx, %edx 
.24636: movq %r13, %rdi 
.24639: shlq $4, %rcx 
.24643: leaq 0x18(%rsp), %rsi 
.24648: addq %rax, %rcx 
.24651: movq 0x20(%rsp), %rax 
.24656: movq %rax, 8(%rcx) 
.24660: callq .26896 
.24665: testb %al, %al 
.24667: jne .24475 
.24673: movq %r15, %rdi 
.24676: movslq 4(%rsp), %rbx 
.24681: callq .86080 
.24686: movl $5, %edx 
.24691: leaq .105169(%rip), %rsi 
.24698: xorl %edi, %edi 
.24700: movq %rax, %r14 
.24703: callq .18592 
.24708: movq %r14, %rcx 
.24711: xorl %esi, %esi 
.24713: xorl %edi, %edi 
.24715: movq %rax, %rdx 
.24718: xorl %eax, %eax 
.24720: callq .19552 
.24725: movl $5, %edx 
.24730: leaq .114144(%rip), %rsi 
.24737: xorl %edi, %edi 
.24739: callq .18592 
.24744: xorl %esi, %esi 
.24746: xorl %edi, %edi 
.24748: movq %rax, %rdx 
.24751: xorl %eax, %eax 
.24753: callq .19552 
.24758: movq .148224(%rip), %rdi 
.24765: callq .18128 
.24770: movq .148232(%rip), %rdi 
.24777: jmp .24791 
.24779: movq 0x20(%rdi), %r14 
.24783: callq .18128 
.24788: movq %r14, %rdi 
.24791: testq %rdi, %rdi 
.24794: jne .24779 
.24796: movb $0, .148242(%rip) 
.24803: jmp .25801 
.24808: callq .29056 
.24813: cmpb $0, .148213(%rip) 
.24820: je .25715 
.24826: cmpq $0, .148400(%rip) 
.24834: je .23363 
.24840: callq .41376 
.24845: cmpq $0, .148352(%rip) 
.24853: je .23596 
.24859: movq .144008(%rip), %rdi 
.24866: movq 0x28(%rdi), %rax 
.24870: cmpq %rax, 0x30(%rdi) 
.24874: jbe .26221 
.24880: leaq 1(%rax), %rdx 
.24884: movq %rdx, 0x28(%rdi) 
.24888: movb $0xa, (%rax) 
.24891: addq $1, .147960(%rip) 
.24899: jmp .23422 
.24904: xorl %eax, %eax 
.24906: leaq .147424(%rip), %rsi 
.24913: jmp .24983 
.24920: movl $1, %edx 
.24925: cmpl $0x40, %eax 
.24928: jg .24968 
.24930: leal -0x30(%rax), %edi 
.24933: cmpl $9, %edi 
.24936: jbe .24968 
.24938: subl $0x2d, %ecx 
.24941: cmpl $1, %ecx 
.24944: jbe .25012 
.24946: nopw (%rax, %rax) 
.24952: cmpl $0x7e, %eax 
.24955: je .25012 
.24957: cmpl $0x5f, %eax 
.24960: sete %dl 
.24963: nopl (%rax, %rax) 
.24968: orb %dl, (%rsi, %rax) 
.24971: addq $1, %rax 
.24975: cmpq $0x100, %rax 
.24981: je .25032 
.24983: movl %eax, %ecx 
.24985: cmpq $0x5a, %rax 
.24989: jbe .24920 
.24991: leal -0x61(%rax), %edi 
.24994: movl $1, %edx 
.24999: cmpl $0x19, %edi 
.25002: jbe .24968 
.25004: subl $0x2d, %ecx 
.25007: cmpl $1, %ecx 
.25010: ja .24952 
.25012: movl $1, %edx 
.25017: orb %dl, (%rsi, %rax) 
.25020: addq $1, %rax 
.25024: cmpq $0x100, %rax 
.25030: jne .24983 
.25032: callq .89296 
.25037: testq %rax, %rax 
.25040: je .25732 
.25046: movq %rax, .148360(%rip) 
.25053: jmp .23249 
.25058: movq .143296(%rip), %r15 
.25065: movq .143328(%rip), %r14 
.25072: xorl %edx, %edx 
.25074: xorl %esi, %esi 
.25076: leaq .147872(%rip), %rdi 
.25083: movq %r15, %r8 
.25086: movq %r14, %rcx 
.25089: callq .92800 
.25094: movq %r15, %r8 
.25097: movq %r14, %rcx 
.25100: xorl %edx, %edx 
.25102: xorl %esi, %esi 
.25104: leaq .147776(%rip), %rdi 
.25111: callq .92800 
.25116: jmp .23236 
.25121: leaq .147872(%rip), %rsi 
.25128: leaq .105211(%rip), %rdi 
.25135: callq .30192 
.25140: leaq .147776(%rip), %rsi 
.25147: leaq .105221(%rip), %rdi 
.25154: callq .30192 
.25159: movq .148176(%rip), %rdi 
.25166: callq .84128 
.25171: leaq .141824(%rip), %rdx 
.25178: movl $1, %edi 
.25183: leaq .114056(%rip), %rsi 
.25190: movl %eax, %eax 
.25192: movq (%rdx, %rax, 8), %rdx 
.25196: xorl %eax, %eax 
.25198: callq .19472 
.25203: jmp .23631 
.25208: movl $1, %edi 
.25213: callq .18368 
.25218: cmpl $1, %eax 
.25221: sbbl %eax, %eax 
.25223: addl $2, %eax 
.25226: movl %eax, .148280(%rip) 
.25232: jmp .21998 
.25237: cmpb $0x2b, (%r15) 
.25241: je .26015 
.25247: movl $4, %ecx 
.25252: leaq .100160(%rip), %rdx 
.25259: leaq .141728(%rip), %rsi 
.25266: movq %r15, %rdi 
.25269: callq .54496 
.25274: testq %rax, %rax 
.25277: js .26322 
.25283: cmpq $2, %rax 
.25287: je .26180 
.25293: jg .25630 
.25299: testq %rax, %rax 
.25302: je .26154 
.25308: subq $1, %rax 
.25312: jne .25335 
.25314: leaq .105118(%rip), %rax 
.25321: movq %rax, .143432(%rip) 
.25328: movq %rax, .143424(%rip) 
.25335: callq .27696 
.25340: jmp .23026 
.25345: movl $1, %edx 
.25350: movl $0x20, %esi 
.25355: movq %rax, %rdi 
.25358: callq .84192 
.25363: jmp .22791 
.25368: leaq .105153(%rip), %rdi 
.25375: callq .18192 
.25380: testq %rax, %rax 
.25383: je .25460 
.25385: cmpb $0, (%rax) 
.25388: je .25460 
.25390: cmpb $0, .148242(%rip) 
.25397: je .23046 
.25403: movl $0xd, %edi 
.25408: callq .27456 
.25413: testb %al, %al 
.25415: jne .25448 
.25417: movl $0xe, %edi 
.25422: callq .27456 
.25427: testb %al, %al 
.25429: je .25594 
.25432: addb %al, (%rax) 
.25434: addb %al, 0x1e02e3d(%rax) 
.25435: cmpb $0, .148368(%rip) 
.25439: addl %eax, (%rax) 
.25440: addb %al, (%rax) 
.25441: addb %cl, (%rdi) 
.25442: je .25594 
.25443: testb %dl, -0x3a000000(%rdx) 
.25448: movb $1, .148221(%rip) 
.25449: addl $0x1df8e, %eax 
.25454: addl %ebp, %ecx 
.25455: jmp .23046 
.25456: xchgl %edx, %eax 
.25457: idivb %bh 
.25459: decl -0x73(%rax) 
.25460: leaq .105158(%rip), %rdi 
.25462: cmpl $0x1374b, %eax 
.25467: callq .18192 
.25472: movq %rax, %r15 
.25475: testq %rax, %rax 
.25478: je .25951 
.25484: cmpb $0, (%rax) 
.25487: je .25951 
.25493: leaq .100192(%rip), %r14 
.25500: jmp .25547 
.25502: xorl %eax, %eax 
.25504: movq %r14, %rdi 
.25507: orq $0xffffffffffffffff, %rcx 
.25511: repne scasb (%rdi), %al 
.25513: movq %rcx, %rax 
.25516: leaq .100192(%rip), %rcx 
.25523: notq %rax 
.25526: addq %rax, %r14 
.25529: movq %r14, %rax 
.25532: subq %rcx, %rax 
.25535: cmpq $0x1043, %rax 
.25541: ja .25951 
.25547: movl $5, %edx 
.25552: leaq .105163(%rip), %rsi 
.25559: movq %r14, %rdi 
.25562: callq .18288 
.25567: testl %eax, %eax 
.25569: jne .25502 
.25571: xorl %edx, %edx 
.25573: leaq 5(%r14), %rdi 
.25577: movq %r15, %rsi 
.25580: callq .18896 
.25585: testl %eax, %eax 
.25587: jne .25502 
.25589: jmp .25390 
.25594: movl $0xc, %edi 
.25599: callq .27456 
.25604: testb %al, %al 
.25606: je .23046 
.25612: cmpl $0, .148280(%rip) 
.25619: jne .23046 
.25625: jmp .25448 
.25630: cmpq $3, %rax 
.25634: jne .25335 
.25640: movl $2, %edi 
.25645: callq .60240 
.25650: testb %al, %al 
.25652: je .25335 
.25658: movq .143424(%rip), %rsi 
.25665: movl $2, %edx 
.25670: xorl %edi, %edi 
.25672: callq .18592 
.25677: movq .143432(%rip), %rsi 
.25684: movl $2, %edx 
.25689: xorl %edi, %edi 
.25691: movq %rax, .143424(%rip) 
.25698: callq .18592 
.25703: movq %rax, .143432(%rip) 
.25710: jmp .25335 
.25715: movl $1, %esi 
.25720: xorl %edi, %edi 
.25722: callq .29584 
.25727: jmp .24826 
.25732: leaq .104446(%rip), %rax 
.25739: jmp .25046 
.25744: xorl %edi, %edi 
.25746: callq .52384 
.25751: movl $2, %edi 
.25756: callq .52384 
.25761: cmpq $1, .143472(%rip) 
.25769: jne .24095 
.25775: movq .143480(%rip), %rax 
.25782: cmpb $0x6d, (%rax) 
.25785: jne .24095 
.25791: jmp .24100 
.25796: movslq 4(%rsp), %rbx 
.25801: cmpq $6, .143568(%rip) 
.25809: jne .25390 
.25815: movq .143576(%rip), %rdi 
.25822: movl $6, %edx 
.25827: leaq .105193(%rip), %rsi 
.25834: callq .18288 
.25839: testl %eax, %eax 
.25841: jne .25390 
.25847: movb $1, .148368(%rip) 
.25854: jmp .25390 
.25859: addq $1, %rax 
.25863: movq %rax, 0x18(%rsp) 
.25868: jmp .24475 
.25873: movl $0x28, %edi 
.25878: callq .88256 
.25883: leaq 0x18(%rsp), %rsi 
.25888: movl $1, %edx 
.25893: movq %r13, %rdi 
.25896: movq %rax, %rcx 
.25899: movq .148232(%rip), %rax 
.25906: addq $1, 0x18(%rsp) 
.25912: movq %rcx, .148232(%rip) 
.25919: movq %rax, 0x20(%rcx) 
.25923: movq 0x20(%rsp), %rax 
.25928: movq %rax, 8(%rcx) 
.25932: callq .26896 
.25937: testb %al, %al 
.25939: jne .25963 
.25941: movslq 4(%rsp), %rbx 
.25946: jmp .24725 
.25951: movb $0, .148242(%rip) 
.25958: jmp .25390 
.25963: movq 0x18(%rsp), %rax 
.25968: leaq 1(%rax), %rdx 
.25972: movq %rdx, 0x18(%rsp) 
.25977: cmpb $0x3d, (%rax) 
.25980: jne .25941 
.25982: movq 0x20(%rsp), %rax 
.25987: addq $0x10, %rcx 
.25991: xorl %edx, %edx 
.25993: movq %r13, %rdi 
.25996: movq %rax, 8(%rcx) 
.26000: callq .26896 
.26005: testb %al, %al 
.26007: jne .24475 
.26013: jmp .25941 
.26015: addq $1, %r15 
.26019: movl $0xa, %esi 
.26024: movq %r15, %rdi 
.26027: callq .18704 
.26032: movq %rax, %rbx 
.26035: testq %rax, %rax 
.26038: je .26213 
.26044: leaq 1(%rax), %r14 
.26048: movl $0xa, %esi 
.26053: movq %r14, %rdi 
.26056: callq .18704 
.26061: testq %rax, %rax 
.26064: jne .26272 
.26070: movb $0, (%rbx) 
.26073: movq %r15, .143424(%rip) 
.26080: movq %r14, .143432(%rip) 
.26087: jmp .25335 
.26092: leaq .105005(%rip), %rdi 
.26099: callq .18192 
.26104: movq %rax, %r15 
.26107: testq %rax, %rax 
.26110: jne .22968 
.26116: leaq .104788(%rip), %r15 
.26123: jmp .25247 
.26128: leaq .104988(%rip), %rdi 
.26135: callq .18192 
.26140: testq %rax, %rax 
.26143: jne .23988 
.26149: jmp .24014 
.26154: leaq .105094(%rip), %rax 
.26161: movq %rax, .143432(%rip) 
.26168: movq %rax, .143424(%rip) 
.26175: jmp .25335 
.26180: leaq .105133(%rip), %rax 
.26187: movq %rax, .143424(%rip) 
.26194: leaq .105121(%rip), %rax 
.26201: movq %rax, .143432(%rip) 
.26208: jmp .25335 
.26213: movq %r15, %r14 
.26216: jmp .26073 
.26221: movl $0xa, %esi 
.26226: callq .18768 
.26231: jmp .24891 
.26236: leaq .99994(%rip), %rcx 
.26243: movl $0x670, %edx 
.26248: leaq .104372(%rip), %rsi 
.26255: leaq .114096(%rip), %rdi 
.26262: hlt 
.26267: hlt 
.26272: movq %r15, %rdi 
.26275: callq .86080 
.26280: movl $5, %edx 
.26285: leaq .105016(%rip), %rsi 
.26292: xorl %edi, %edi 
.26294: movq %rax, %r12 
.26297: callq .18592 
.26302: movq %r12, %rcx 
.26305: xorl %esi, %esi 
.26307: movl $2, %edi 
.26312: movq %rax, %rdx 
.26315: xorl %eax, %eax 
.26317: callq .19552 
.26322: movq %rax, %rdx 
.26325: movq %r15, %rsi 
.26328: leaq .105045(%rip), %rdi 
.26335: callq .54768 
.26340: movq .144064(%rip), %rbp 
.26347: movl $5, %edx 
.26352: xorl %edi, %edi 
.26354: leaq .105056(%rip), %rsi 
.26361: leaq .141728(%rip), %rbx 
.26368: callq .18592 
.26373: movq %rbp, %rsi 
.26376: leaq .105078(%rip), %rbp 
.26383: movq %rax, %rdi 
.26386: callq .19024 
.26391: leaq .104765(%rip), %rcx 
.26398: movq .144064(%rip), %rdi 
.26405: addq $8, %rbx 
.26409: movq %rbp, %rdx 
.26412: xorl %eax, %eax 
.26414: movl $1, %esi 
.26419: callq .19744 
.26424: movq (%rbx), %rcx 
.26427: testq %rcx, %rcx 
.26430: jne .26398 
.26432: movq .144064(%rip), %rbp 
.26439: movl $5, %edx 
.26444: leaq .113944(%rip), %rsi 
.26451: xorl %edi, %edi 
.26453: callq .18592 
.26458: movq %rax, %rdi 
.26461: movq %rbp, %rsi 
.26464: callq .19024 
.26469: movl $2, %edi 
.26474: callq .52384 
.26479: callq .88880 
.26484: movq .144024(%rip), %r8 
.26491: movl 0x20(%rsp), %esi 
.26495: xorl %edx, %edx 
.26497: movl %eax, %edi 
.26499: leaq .140032(%rip), %rcx 
.26506: callq .90736 
.26511: leaq .99832(%rip), %rcx 
.26518: movl $0x403, %edx 
.26523: leaq .104372(%rip), %rsi 
.26530: leaq .114000(%rip), %rdi 
.26537: hlt 
.26542: leaq .99994(%rip), %rcx 
.26549: movl $0x63c, %edx 
.26554: leaq .104372(%rip), %rsi 
.26561: leaq .105205(%rip), %rdi 
.26568: hlt 
.26885: nopw %cs:(%rax, %rax) 
.26896: movq (%rsi), %r9 
.26899: movq (%rdi), %r11 
.26902: pushq %r12 
.26904: xorl %eax, %eax 
.26906: pushq %rbp 
.26907: leaq .98336(%rip), %r10 
.26914: pushq %rbx 
.26915: movl %edx, %ebx 
.26917: movzbl (%r9), %r8d 
.26921: cmpb $0x5c, %r8b 
.26925: je .26970 
.26927: jg .27016 
.26929: cmpb $0x3d, %r8b 
.26933: je .27312 
.26939: jle .27072 
.26945: addq $1, %r9 
.26949: movb %r8b, (%r11) 
.26952: addq $1, %rax 
.26956: addq $1, %r11 
.26960: movzbl (%r9), %r8d 
.26964: cmpb $0x5c, %r8b 
.26968: jne .26927 
.26970: movzbl 1(%r9), %ebp 
.26975: addq $2, %r9 
.26979: testb %bpl, %bpl 
.26982: je .27297 
.26988: leal -0x30(%rbp), %r12d 
.26992: cmpb $0x48, %r12b 
.26996: ja .27115 
.26998: movzbl %r12b, %r8d 
.27002: movslq (%r10, %r8, 4), %r8 
.27006: addq %r10, %r8 
.27009: jmpq *%r8 
.27016: cmpb $0x5e, %r8b 
.27020: jne .26945 
.27022: movzbl 1(%r9), %r8d 
.27027: leaq 1(%r9), %r12 
.27031: leal -0x40(%r8), %ebp 
.27035: cmpb $0x3e, %bpl 
.27039: ja .27288 
.27045: addq $2, %r9 
.27049: andl $0x1f, %r8d 
.27053: movb %r8b, (%r11) 
.27056: addq $1, %rax 
.27060: addq $1, %r11 
.27064: jmp .26917 
.27072: testb %r8b, %r8b 
.27075: je .27087 
.27077: cmpb $0x3a, %r8b 
.27081: jne .26945 
.27087: movl $1, %r8d 
.27093: movq %r11, (%rdi) 
.27096: popq %rbx 
.27097: movq %r9, (%rsi) 
.27100: popq %rbp 
.27101: movq %rax, (%rcx) 
.27104: popq %r12 
.27106: movl %r8d, %eax 
.27109: ret 
.27110: movl $0x1b, %ebp 
.27115: movb %bpl, (%r11) 
.27118: addq $1, %rax 
.27122: addq $1, %r11 
.27126: jmp .26917 
.27131: movl $7, %ebp 
.27136: jmp .27115 
.27138: xorl %r8d, %r8d 
.27141: movzbl (%r9), %ebp 
.27145: cmpb $0x46, %bpl 
.27149: jg .27190 
.27151: cmpb $0x40, %bpl 
.27155: jg .27264 
.27157: leal -0x30(%rbp), %r12d 
.27161: cmpb $9, %r12b 
.27165: ja .27053 
.27167: addq $1, %r9 
.27171: shll $4, %r8d 
.27175: leal -0x30(%rbp, %r8), %r8d 
.27180: movzbl (%r9), %ebp 
.27184: cmpb $0x46, %bpl 
.27188: jle .27151 
.27190: leal -0x61(%rbp), %r12d 
.27194: cmpb $5, %r12b 
.27198: ja .27053 
.27204: shll $4, %r8d 
.27208: addq $1, %r9 
.27212: leal -0x57(%rbp, %r8), %r8d 
.27217: jmp .27141 
.27224: addq $1, %r9 
.27228: leal -0x30(%r8, %r12, 8), %r12d 
.27233: movzbl (%r9), %r8d 
.27237: leal -0x30(%r8), %ebp 
.27241: cmpb $7, %bpl 
.27245: jbe .27224 
.27247: movb %r12b, (%r11) 
.27250: addq $1, %rax 
.27254: addq $1, %r11 
.27258: jmp .26917 
.27264: shll $4, %r8d 
.27268: addq $1, %r9 
.27272: leal -0x37(%rbp, %r8), %r8d 
.27277: jmp .27141 
.27288: cmpb $0x3f, %r8b 
.27292: je .27328 
.27294: movq %r12, %r9 
.27297: xorl %r8d, %r8d 
.27300: jmp .27093 
.27312: testb %bl, %bl 
.27314: je .26945 
.27320: movl %edx, %r8d 
.27323: jmp .27093 
.27328: movb $0x7f, (%r11) 
.27332: addq $1, %rax 
.27336: addq $1, %r11 
.27340: movq %r12, %r9 
.27343: jmp .26917 
.27348: movl $0xb, %ebp 
.27353: jmp .27115 
.27358: movl $0xa, %ebp 
.27363: jmp .27115 
.27368: movl $0xd, %ebp 
.27373: jmp .27115 
.27378: movl $0x7f, %ebp 
.27383: jmp .27115 
.27388: movl $0x20, %ebp 
.27393: jmp .27115 
.27398: movl $8, %ebp 
.27403: jmp .27115 
.27408: movl $0xc, %ebp 
.27413: jmp .27115 
.27418: movl $9, %ebp 
.27423: jmp .27115 
.40976: movq %r13, %rbp 
.40979: testq %rbx, %rbx 
.40982: jne .41184 
.40988: movq %rbp, %rsi 
.40991: movq %r12, %rdi 
.40994: addq $1, %rbx 
.40998: callq .36528 
.41003: cmpq %rbx, .148400(%rip) 
.41010: jbe .41224 
.41016: movq .148384(%rip), %rax 
.41023: cmpq $0, .148144(%rip) 
.41031: movq (%rax, %rbx, 8), %r12 
.41035: je .40976 
.41037: movq %r12, %rdi 
.41040: callq .39760 
.41045: testq %rbx, %rbx 
.41048: je .41272 
.41054: movq .148144(%rip), %rdx 
.41061: leaq 2(%r13), %rbp 
.41065: leaq (%rax, %rbp), %rcx 
.41069: testq %rdx, %rdx 
.41072: je .41094 
.41074: cmpq %rcx, %rdx 
.41077: jbe .41200 
.41079: movq $-3, %rdx 
.41086: subq %rax, %rdx 
.41089: cmpq %r13, %rdx 
.41092: jb .41200 
.41094: movq %rcx, %r13 
.41097: nopl (%rax) 
.41104: movl $0x20, %r8d 
.41110: movl $0x20, %edx 
.41115: movq .144008(%rip), %rdi 
.41122: movq 0x28(%rdi), %rax 
.41126: cmpq 0x30(%rdi), %rax 
.41130: jae .41288 
.41136: leaq 1(%rax), %rcx 
.41140: movq %rcx, 0x28(%rdi) 
.41144: movb %r14b, (%rax) 
.41147: movq .144008(%rip), %rdi 
.41154: movq 0x28(%rdi), %rax 
.41158: cmpq 0x30(%rdi), %rax 
.41162: jae .41328 
.41168: leaq 1(%rax), %rcx 
.41172: movq %rcx, 0x28(%rdi) 
.41176: movb %dl, (%rax) 
.41178: jmp .40988 
.41184: leaq 2(%r13), %rbp 
.41188: movq %rbp, %r13 
.41191: jmp .41104 
.41200: movq %rax, %r13 
.41203: movl $0xa, %r8d 
.41209: movl $0xa, %edx 
.41214: xorl %ebp, %ebp 
.41216: jmp .41115 
.41224: movq .144008(%rip), %rdi 
.41231: movq 0x28(%rdi), %rax 
.41235: cmpq 0x30(%rdi), %rax 
.41239: jae .41344 
.41241: leaq 1(%rax), %rdx 
.41245: movq %rdx, 0x28(%rdi) 
.41249: movb $0xa, (%rax) 
.41252: addq $0x18, %rsp 
.41256: popq %rbx 
.41257: popq %rbp 
.41258: popq %r12 
.41260: popq %r13 
.41262: popq %r14 
.41264: popq %r15 
.41266: ret 
.41272: movq %r13, %rbp 
.41275: addq %rax, %r13 
.41278: jmp .40988 
.41288: movl %r15d, %esi 
.41291: movl %r8d, 0xc(%rsp) 
.41296: movb %dl, 0xb(%rsp) 
.41300: callq .18768 
.41305: movzbl 0xb(%rsp), %edx 
.41310: movl 0xc(%rsp), %r8d 
.41315: jmp .41147 
.41328: movl %r8d, %esi 
.41331: callq .18768 
.41336: jmp .40988 
.41344: addq $0x18, %rsp 
.41348: movl $0xa, %esi 
.41353: popq %rbx 
.41354: popq %rbp 
.41355: popq %r12 
.41357: popq %r13 
.41359: popq %r14 
.41361: popq %r15 
.41363: jmp .18768 
.41380: addl %eax, (%rax) 
.41382: addb $0xf, %al 
.41384: xchgl %edi, 3(%rbp) 
.41387: addb %al, (%rax) 
.41389: pushq %r15 
.41391: leaq .98628(%rip), %rdx 
.41398: pushq %r14 
.41400: pushq %r13 
.41402: pushq %r12 
.41404: pushq %rbp 
.41405: pushq %rbx 
.41406: subq $0x28, %rsp 
.41410: movl .148280(%rip), %eax 
.41416: movslq (%rdx, %rax, 4), %rax 
.41420: addq %rdx, %rax 
.41423: jmpq *%rax 
.41500: movq 0x10(%r14), %rax 
.41504: movq (%rax), %r12 
.41507: callq .36528 
.41512: cmpq $1, .148400(%rip) 
.41520: jbe .42192 
.41526: xorl %r13d, %r13d 
.41529: movl $1, %ebx 
.41534: jmp .41629 
.41536: movq .144008(%rip), %rdi 
.41543: movq 0x28(%rdi), %rax 
.41547: cmpq 0x30(%rdi), %rax 
.41551: jae .42240 
.41557: leaq 1(%rax), %rdx 
.41561: xorl %r13d, %r13d 
.41564: movq %rdx, 0x28(%rdi) 
.41568: movb $0xa, (%rax) 
.41571: movq .148384(%rip), %rax 
.41578: movq %r13, %rsi 
.41581: movq (%rax, %rbx, 8), %r12 
.41585: addq $1, %rbx 
.41588: addl %ecx, -0x19(%rcx, %rcx, 4) 
.41589: movq %r12, %rdi 
.41592: callq .36528 
.41597: movq %r12, %rdi 
.41600: callq .39760 
.41605: movq 0x10(%r14), %rdx 
.41609: cmpq .148400(%rip), %rbx 
.41616: movq %rax, %r15 
.41619: movq (%rdx, %rbp, 8), %r12 
.41623: jae .42192 
.41629: movq %rbx, %rax 
.41632: xorl %edx, %edx 
.41634: divq 8(%rsp) 
.41639: movq %rdx, %rbp 
.41642: testq %rdx, %rdx 
.41645: je .41536 
.41647: addq %r13, %r12 
.41650: leaq (%r15, %r13), %rdi 
.41654: movq %r12, %rsi 
.41657: movq %r12, %r13 
.41660: callq .29984 
.41665: jmp .41571 
.42119: addq $0x28, %rsp 
.42123: popq %rbx 
.42124: popq %rbp 
.42125: popq %r12 
.42127: popq %r13 
.42129: popq %r14 
.42131: popq %r15 
.42133: ret 
.42192: movq .144008(%rip), %rdi 
.42199: movq 0x28(%rdi), %rax 
.42203: cmpq 0x30(%rdi), %rax 
.42207: jae .42258 
.42209: leaq 1(%rax), %rdx 
.42213: movq %rdx, 0x28(%rdi) 
.42217: movb $0xa, (%rax) 
.42220: jmp .42119 
.42240: movl $0xa, %esi 
.42245: xorl %r13d, %r13d 
.42248: callq .18768 
.42253: jmp .41571 
.42258: addq $0x28, %rsp 
.42262: movl $0xa, %esi 
.42267: popq %rbx 
.42268: popq %rbp 
.42269: popq %r12 
.42271: popq %r13 
.42273: popq %r14 
.42275: popq %r15 
.42277: jmp .18768 
