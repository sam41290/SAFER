.65431: nopw (%rax, %rax) 
.65440: endbr64 
.65444: pushq %r15 
.65446: pushq %r14 
.65448: pushq %r13 
.65450: movq %rcx, %r13 
.65453: pushq %r12 
.65455: pushq %rbp 
.65456: movq %rsi, %rbp 
.65459: pushq %rbx 
.65460: movq %rdi, %rbx 
.65463: subq $0x98, %rsp 
.65470: movq %r8, 0x10(%rsp) 
.65475: movl %edx, 0x40(%rsp) 
.65479: movq %fs:0x28, %rax 
.65488: movq %rax, 0x88(%rsp) 
.65496: xorl %eax, %eax 
.65498: movl %edx, %eax 
.65500: andl $0x20, %edx 
.65503: andl $3, %eax 
.65506: cmpl $1, %edx 
.65509: movl %edx, 0x34(%rsp) 
.65513: movl %eax, 0x18(%rsp) 
.65517: sbbl %eax, %eax 
.65519: andl $0xffffffe8, %eax 
.65522: addl $0x400, %eax 
.65527: movl %eax, 0x30(%rsp) 
.65531: callq .18432 
.65536: movq (%rax), %r15 
.65539: movq %rax, %r12 
.65542: movq %r15, %rdi 
.65545: callq .18624 
.65550: movl $1, %edx 
.65555: movq %rax, %r14 
.65558: subq $1, %rax 
.65562: cmpq $0x10, %rax 
.65566: leaq .105203(%rip), %rax 
.65573: cmovaeq %rax, %r15 
.65577: movq 0x10(%r12), %rax 
.65582: movq 8(%r12), %r12 
.65587: cmovaeq %rdx, %r14 
.65591: movq %r12, %rdi 
.65594: movq %rax, 0x38(%rsp) 
.65599: callq .18624 
.65604: movq 0x10(%rsp), %rcx 
.65609: cmpq $0x10, %rax 
.65613: leaq .104446(%rip), %rax 
.65620: cmovaq %rax, %r12 
.65624: leaq 0x287(%rbp), %rax 
.65631: movq %rax, 8(%rsp) 
.65636: cmpq %r13, %rcx 
.65639: ja .66040 
.65645: movq %r13, %rax 
.65648: xorl %edx, %edx 
.65650: divq %rcx 
.65653: movq %rax, %rsi 
.65656: testq %rdx, %rdx 
.65659: jne .65685 
.65661: movq %rbx, %rdi 
.65664: xorl %edx, %edx 
.65666: imulq %rax, %rdi 
.65670: movq %rdi, %rax 
.65673: divq %rsi 
.65676: cmpq %rbx, %rax 
.65679: je .66968 
.65685: movq %r13, 0x20(%rsp) 
.65690: fildll 0x20(%rsp) 
.65694: testq %r13, %r13 
.65697: js .66768 
.65703: movq 0x10(%rsp), %rax 
.65708: movq %rax, 0x20(%rsp) 
.65713: fildll 0x20(%rsp) 
.65717: testq %rax, %rax 
.65720: js .66736 
.65726: movq %rbx, 0x20(%rsp) 
.65731: fdivrp %st(1) 
.65733: fildll 0x20(%rsp) 
.65737: testq %rbx, %rbx 
.65740: js .66704 
.65746: fmulp %st(1) 
.65748: testb $0x10, 0x40(%rsp) 
.65753: je .66496 
.65759: fildl 0x30(%rsp) 
.65763: xorl %ebx, %ebx 
.65765: fld %st(0) 
.65767: jmp .65780 
.65776: fstp %st(1) 
.65778: fxch %st(2) 
.65780: fld %st(0) 
.65782: addl $1, %ebx 
.65785: fmul %st(2) 
.65787: fxch %st(3) 
.65789: fcomi %st(3) 
.65791: jb .65808 
.65793: cmpl $8, %ebx 
.65796: jne .65776 
.65798: fstp %st(2) 
.65800: fstp %st(2) 
.65802: jmp .65812 
.65808: fstp %st(2) 
.65810: fstp %st(2) 
.65812: movl 0x34(%rsp), %edi 
.65816: leaq 1(%r14), %r15 
.65820: fdivp %st(1) 
.65822: xorl %eax, %eax 
.65824: testl %edi, %edi 
.65826: movl 0x18(%rsp), %edi 
.65830: sete %al 
.65833: leaq 2(%r14, %rax), %r14 
.65838: cmpl $1, %edi 
.65841: je .67216 
.65847: fldt .114672(%rip) 
.65853: fcomip %st(1) 
.65855: ja .66936 
.65861: fld %st(0) 
.65863: fstpt 0x20(%rsp) 
.65867: movq $-1, %rdx 
.65874: movq %rbp, %rdi 
.65877: xorl %eax, %eax 
.65879: subq $0x10, %rsp 
.65883: movl $1, %esi 
.65888: leaq .114590(%rip), %rcx 
.65895: fstpt (%rsp) 
.65898: callq .19856 
.65903: movq %rbp, %rdi 
.65906: callq .18624 
.65911: popq %rsi 
.65912: popq %rdi 
.65913: fldt 0x20(%rsp) 
.65917: cmpq %r14, %rax 
.65920: movq %rax, %rdx 
.65923: jbe .67000 
.65929: flds .114660(%rip) 
.65935: fmul %st(0), %st(1) 
.65937: fldt .114672(%rip) 
.65943: fcomip %st(2) 
.65945: jbe .65973 
.65947: fstps 0x20(%rsp) 
.65951: subq $0x10, %rsp 
.65955: fstpt (%rsp) 
.65958: movl 0x28(%rsp), %edi 
.65962: callq .65248 
.65967: popq %rax 
.65968: popq %rdx 
.65969: flds 0x20(%rsp) 
.65973: fdivrp %st(1) 
.65975: subq $0x10, %rsp 
.65979: movq $-1, %rdx 
.65986: movq %rbp, %rdi 
.65989: leaq .114584(%rip), %rcx 
.65996: movl $1, %esi 
.66001: xorl %eax, %eax 
.66003: fstpt (%rsp) 
.66006: callq .19856 
.66011: movq %rbp, %rdi 
.66014: callq .18624 
.66019: popq %r14 
.66021: popq %r15 
.66023: movq %rax, %rdx 
.66026: movq %rax, %r14 
.66029: jmp .66578 
.66040: testq %r13, %r13 
.66043: je .65685 
.66049: movq 0x10(%rsp), %rax 
.66054: xorl %edx, %edx 
.66056: divq %r13 
.66059: movq %rax, %r8 
.66062: testq %rdx, %rdx 
.66065: jne .65685 
.66071: movq %rbx, %rax 
.66074: xorl %edx, %edx 
.66076: divq %r8 
.66079: movq %rax, %rdi 
.66082: leaq (%rdx, %rdx, 4), %rax 
.66086: xorl %edx, %edx 
.66088: addq %rax, %rax 
.66091: divq %r8 
.66094: addq %rdx, %rdx 
.66097: movl %eax, %esi 
.66099: cmpq %rdx, %r8 
.66102: jbe .67376 
.66108: xorl %ecx, %ecx 
.66110: testq %rdx, %rdx 
.66113: setne %cl 
.66116: movl 0x40(%rsp), %r10d 
.66121: andl $0x10, %r10d 
.66125: je .66987 
.66131: movl 0x30(%rsp), %r8d 
.66136: xorl %ebx, %ebx 
.66138: movq %r8, %r11 
.66141: cmpq %rdi, %r8 
.66144: jbe .66853 
.66150: cmpl $1, 0x18(%rsp) 
.66155: movq 8(%rsp), %r8 
.66160: je .67328 
.66166: movl 0x18(%rsp), %r11d 
.66171: testl %r11d, %r11d 
.66174: jne .66208 
.66176: addl %esi, %ecx 
.66178: testl %ecx, %ecx 
.66180: jle .66208 
.66182: addq $1, %rdi 
.66186: testl %r10d, %r10d 
.66189: je .66208 
.66191: movl 0x30(%rsp), %eax 
.66195: cmpq %rdi, %rax 
.66198: je .67405 
.66204: nopl (%rax) 
.66208: movabsq $0xcccccccccccccccd, %rcx 
.66218: movq %r8, %r15 
.66221: nopl (%rax) 
.66224: movq %rdi, %rax 
.66227: movq %rdi, %rsi 
.66230: subq $1, %r15 
.66234: mulq %rcx 
.66237: shrq $3, %rdx 
.66241: leaq (%rdx, %rdx, 4), %rax 
.66245: addq %rax, %rax 
.66248: subq %rax, %rsi 
.66251: movq %rsi, %rax 
.66254: addl $0x30, %eax 
.66257: movb %al, (%r15) 
.66260: movq %rdi, %rax 
.66263: movq %rdx, %rdi 
.66266: cmpq $9, %rax 
.66270: ja .66224 
.66272: testb $4, 0x40(%rsp) 
.66277: je .66612 
.66283: movq %r8, %r14 
.66286: movq %r12, %rdi 
.66289: movq %r8, 0x48(%rsp) 
.66294: movq $-1, %r13 
.66301: callq .18624 
.66306: subq %r15, %r14 
.66309: leaq 0x50(%rsp), %rdi 
.66314: movq %r15, %rsi 
.66317: movq %r14, %rdx 
.66320: movl $0x29, %ecx 
.66325: movq %rax, 0x18(%rsp) 
.66330: movq %r12, %r15 
.66333: movq %rdi, 0x20(%rsp) 
.66338: callq .19136 
.66343: movl %ebx, 0x44(%rsp) 
.66347: movq 0x38(%rsp), %r12 
.66352: movq %r14, %rbx 
.66355: movq 0x48(%rsp), %r8 
.66360: movq 0x20(%rsp), %r14 
.66365: movq %rbp, 0x38(%rsp) 
.66370: movq %r13, %rbp 
.66373: movq 0x18(%rsp), %r13 
.66378: jmp .66444 
.66384: cmpq %rbx, %rbp 
.66387: cmovaq %rbx, %rbp 
.66391: subq %rbp, %rbx 
.66394: leaq (%r14, %rbx), %rsi 
.66398: subq %rbp, %r8 
.66401: movq %rbp, %rdx 
.66404: movq %r8, %rdi 
.66407: callq .19168 
.66412: movq %rax, %r8 
.66415: testq %rbx, %rbx 
.66418: je .66800 
.66424: subq %r13, %r8 
.66427: movq %r13, %rdx 
.66430: movq %r15, %rsi 
.66433: movq %r8, %rdi 
.66436: callq .19168 
.66441: movq %rax, %r8 
.66444: movzbl (%r12), %eax 
.66449: testb %al, %al 
.66451: je .66384 
.66453: cmpb $0x7e, %al 
.66455: ja .66784 
.66461: movzbl %al, %r9d 
.66465: cmpq %rbx, %r9 
.66468: cmovaq %rbx, %r9 
.66472: subq %r9, %rbx 
.66475: movq %r9, %rbp 
.66478: leaq (%r14, %rbx), %rsi 
.66482: addq $1, %r12 
.66486: jmp .66398 
.66496: movl 0x18(%rsp), %edi 
.66500: cmpl $1, %edi 
.66503: je .66519 
.66505: fldt .114672(%rip) 
.66511: fcomip %st(1) 
.66513: ja .66912 
.66519: subq $0x10, %rsp 
.66523: movq $-1, %rdx 
.66530: movq %rbp, %rdi 
.66533: xorl %eax, %eax 
.66535: leaq .114584(%rip), %rcx 
.66542: movl $1, %esi 
.66547: fstpt (%rsp) 
.66550: movl $0xffffffff, %ebx 
.66555: callq .19856 
.66560: movq %rbp, %rdi 
.66563: callq .18624 
.66568: popq %r8 
.66570: popq %r9 
.66572: movq %rax, %rdx 
.66575: movq %rax, %r14 
.66578: movq 8(%rsp), %r15 
.66583: movq %rbp, %rsi 
.66586: subq %rdx, %r15 
.66589: movq %r15, %rdi 
.66592: callq .19536 
.66597: leaq (%r15, %r14), %r8 
.66601: testb $4, 0x40(%rsp) 
.66606: jne .66283 
.66612: testb $0x80, 0x40(%rsp) 
.66617: je .66647 
.66619: cmpl $-1, %ebx 
.66622: je .67040 
.66628: movl 0x40(%rsp), %eax 
.66632: andl $0x100, %eax 
.66637: movl %eax, %ecx 
.66639: orl %ebx, %ecx 
.66641: jne .67304 
.66647: movq 8(%rsp), %rax 
.66652: movb $0, (%rax) 
.66655: movq 0x88(%rsp), %rax 
.66663: xorq %fs:0x28, %rax 
.66672: jne .68005 
.66678: addq $0x98, %rsp 
.66685: movq %r15, %rax 
.66688: popq %rbx 
.66689: popq %rbp 
.66690: popq %r12 
.66692: popq %r13 
.66694: popq %r14 
.66696: popq %r15 
.66698: ret 
.66704: fadds .114568(%rip) 
.66710: fmulp %st(1) 
.66712: testb $0x10, 0x40(%rsp) 
.66717: jne .65759 
.66723: jmp .66496 
.66736: fadds .114568(%rip) 
.66742: movq %rbx, 0x20(%rsp) 
.66747: fdivrp %st(1) 
.66749: fildll 0x20(%rsp) 
.66753: testq %rbx, %rbx 
.66756: jns .65746 
.66762: jmp .66704 
.66768: fadds .114568(%rip) 
.66774: jmp .65703 
.66784: movq %rbx, %rbp 
.66787: movq %r14, %rsi 
.66790: xorl %ebx, %ebx 
.66792: jmp .66482 
.66800: movl 0x44(%rsp), %ebx 
.66804: movq 0x38(%rsp), %rbp 
.66809: movq %rax, %r15 
.66812: jmp .66612 
.66824: testl %ecx, %ecx 
.66826: setne %cl 
.66829: movzbl %cl, %ecx 
.66832: addl $1, %ebx 
.66835: cmpq %r9, %r8 
.66838: ja .67488 
.66844: cmpl $8, %ebx 
.66847: je .66150 
.66853: movq %rdi, %rax 
.66856: xorl %edx, %edx 
.66858: divq %r8 
.66861: movq %rax, %r9 
.66864: leal (%rdx, %rdx, 4), %eax 
.66867: xorl %edx, %edx 
.66869: leal (%rsi, %rax, 2), %eax 
.66872: movl %ecx, %esi 
.66874: movq %r9, %rdi 
.66877: divl %r11d 
.66880: sarl $1, %esi 
.66882: leal (%rsi, %rdx, 2), %edx 
.66885: movl %eax, %esi 
.66887: addl %edx, %ecx 
.66889: cmpl %edx, %r11d 
.66892: ja .66824 
.66894: cmpl %ecx, %r11d 
.66897: setb %cl 
.66900: movzbl %cl, %ecx 
.66903: addl $2, %ecx 
.66906: jmp .66832 
.66912: subq $0x10, %rsp 
.66916: fstpt (%rsp) 
.66919: callq .65248 
.66924: popq %r10 
.66926: popq %r11 
.66928: jmp .66519 
.66936: subq $0x10, %rsp 
.66940: fld %st(0) 
.66942: fstpt (%rsp) 
.66945: fstpt 0x30(%rsp) 
.66949: callq .65248 
.66954: popq %rcx 
.66955: popq %rsi 
.66956: fldt 0x20(%rsp) 
.66960: jmp .65863 
.66968: movl 0x40(%rsp), %r10d 
.66973: xorl %ecx, %ecx 
.66975: xorl %esi, %esi 
.66977: andl $0x10, %r10d 
.66981: jne .66131 
.66987: movl $0xffffffff, %ebx 
.66992: jmp .66150 
.67000: testb $8, 0x40(%rsp) 
.67005: je .67024 
.67007: cmpb $0x30, -1(%rbp, %rdx) 
.67012: je .67648 
.67018: fstp %st(0) 
.67020: jmp .67026 
.67024: fstp %st(0) 
.67026: movq %rdx, %r14 
.67029: subq %r15, %r14 
.67032: jmp .66578 
.67040: movq 0x10(%rsp), %rcx 
.67045: cmpq $1, %rcx 
.67049: jbe .67703 
.67055: movl 0x30(%rsp), %edx 
.67059: movl $1, %ebx 
.67064: movl $1, %eax 
.67069: nopl (%rax) 
.67072: imulq %rdx, %rax 
.67076: cmpq %rax, %rcx 
.67079: jbe .67089 
.67081: addl $1, %ebx 
.67084: cmpl $8, %ebx 
.67087: jne .67072 
.67089: movl 0x40(%rsp), %ecx 
.67093: movl %ecx, %eax 
.67095: andl $0x100, %eax 
.67100: andl $0x40, %ecx 
.67103: je .67132 
.67105: leaq 0x288(%rbp), %rcx 
.67112: movb $0x20, 0x287(%rbp) 
.67119: movq %rcx, 8(%rsp) 
.67124: testl %ebx, %ebx 
.67126: je .68039 
.67132: cmpl $1, %ebx 
.67135: jne .67151 
.67137: movl 0x34(%rsp), %r9d 
.67142: testl %r9d, %r9d 
.67145: je .67448 
.67151: movslq %ebx, %rbx 
.67154: leaq .114648(%rip), %rcx 
.67161: movq 8(%rsp), %rsi 
.67166: movzbl (%rcx, %rbx), %ecx 
.67170: leaq 1(%rsi), %rdx 
.67174: movb %cl, (%rsi) 
.67176: testl %eax, %eax 
.67178: je .67468 
.67184: movl 0x34(%rsp), %r8d 
.67189: testl %r8d, %r8d 
.67192: jne .67392 
.67198: leaq 1(%rdx), %rax 
.67202: movb $0x42, (%rdx) 
.67205: movq %rax, 8(%rsp) 
.67210: jmp .66647 
.67216: subq $0x10, %rsp 
.67220: leaq .114590(%rip), %rcx 
.67227: movq %rbp, %rdi 
.67230: xorl %eax, %eax 
.67232: fld %st(0) 
.67234: fstpt (%rsp) 
.67237: movq $-1, %rdx 
.67244: movl $1, %esi 
.67249: fstpt 0x30(%rsp) 
.67253: callq .19856 
.67258: movq %rbp, %rdi 
.67261: callq .18624 
.67266: movq %rax, %rdx 
.67269: popq %rax 
.67270: popq %rcx 
.67271: fldt 0x20(%rsp) 
.67275: cmpq %r14, %rdx 
.67278: jbe .67000 
.67284: flds .114660(%rip) 
.67290: fmul %st(0), %st(1) 
.67292: jmp .65973 
.67304: testb $0x40, 0x40(%rsp) 
.67309: je .67124 
.67315: jmp .67105 
.67328: movq %rdi, %rax 
.67331: movslq %ecx, %rcx 
.67334: andl $1, %eax 
.67337: addq %rcx, %rax 
.67340: setne %al 
.67343: movzbl %al, %eax 
.67346: addl %eax, %esi 
.67348: cmpl $5, %esi 
.67351: jle .66208 
.67357: movq 8(%rsp), %r8 
.67362: jmp .66182 
.67376: setb %cl 
.67379: movzbl %cl, %ecx 
.67382: addl $2, %ecx 
.67385: jmp .66116 
.67392: movb $0x69, 1(%rsi) 
.67396: leaq 2(%rsi), %rdx 
.67400: jmp .67198 
.67405: cmpl $8, %ebx 
.67408: je .66208 
.67414: addl $1, %ebx 
.67417: testb $8, 0x40(%rsp) 
.67422: je .67816 
.67428: movb $0x31, -1(%r8) 
.67433: leaq -1(%r8), %r15 
.67437: jmp .66601 
.67448: movq 8(%rsp), %rcx 
.67453: movb $0x6b, (%rcx) 
.67456: leaq 1(%rcx), %rdx 
.67460: testl %eax, %eax 
.67462: jne .67198 
.67468: movq %rdx, 8(%rsp) 
.67473: jmp .66647 
.67488: cmpq $9, %r9 
.67492: ja .66150 
.67498: cmpl $1, 0x18(%rsp) 
.67503: je .67685 
.67509: movl 0x18(%rsp), %r13d 
.67514: testl %r13d, %r13d 
.67517: sete %dl 
.67520: testl %ecx, %ecx 
.67522: setg %sil 
.67526: andl %esi, %edx 
.67528: testb %dl, %dl 
.67530: jne .67672 
.67536: testl %eax, %eax 
.67538: jne .68031 
.67544: movq 8(%rsp), %r8 
.67549: testb $8, 0x40(%rsp) 
.67554: jne .67616 
.67556: movl $0x30, %eax 
.67561: leaq 0x286(%rbp), %r8 
.67568: movb %al, 0x286(%rbp) 
.67574: movl %r14d, %r9d 
.67577: subq %r14, %r8 
.67580: cmpl $8, %r14d 
.67584: jae .67710 
.67586: testb $4, %r14b 
.67590: jne .67984 
.67596: testl %r9d, %r9d 
.67599: je .67614 
.67601: movzbl (%r15), %eax 
.67605: movb %al, (%r8) 
.67608: testb $2, %r9b 
.67612: jne .67634 
.67614: xorl %ecx, %ecx 
.67616: cmpl $1, 0x18(%rsp) 
.67621: je .66208 
.67627: xorl %esi, %esi 
.67629: jmp .66166 
.67634: movzwl -2(%r15, %r9), %eax 
.67640: movw %ax, -2(%r8, %r9) 
.67646: jmp .67614 
.67648: flds .114660(%rip) 
.67654: cmpl $1, 0x18(%rsp) 
.67659: fmul %st(0), %st(1) 
.67661: jne .65937 
.67667: jmp .65973 
.67672: leal 1(%rax), %edx 
.67675: cmpl $9, %eax 
.67678: je .67795 
.67680: leal 0x30(%rdx), %eax 
.67683: jmp .67561 
.67685: movl %eax, %edx 
.67687: andl $1, %edx 
.67690: addl %ecx, %edx 
.67692: cmpl $2, %edx 
.67695: setg %dl 
.67698: jmp .67528 
.67703: xorl %ebx, %ebx 
.67705: jmp .66628 
.67710: movq (%r15), %rax 
.67713: leaq 8(%r8), %rcx 
.67717: movq %r8, %r9 
.67720: movq %r15, %rsi 
.67723: andq $0xfffffffffffffff8, %rcx 
.67727: movq %rax, (%r8) 
.67730: subq %rcx, %r9 
.67733: movl %r14d, %eax 
.67736: movq -8(%r15, %rax), %rdx 
.67741: subq %r9, %rsi 
.67744: addl %r14d, %r9d 
.67747: andl $0xfffffff8, %r9d 
.67751: movq %rdx, -8(%r8, %rax) 
.67756: cmpl $8, %r9d 
.67760: jb .67614 
.67766: andl $0xfffffff8, %r9d 
.67770: xorl %eax, %eax 
.67772: movl %eax, %edx 
.67774: addl $8, %eax 
.67777: movq (%rsi, %rdx), %r11 
.67781: movq %r11, (%rcx, %rdx) 
.67785: cmpl %r9d, %eax 
.67788: jb .67772 
.67790: jmp .67614 
.67795: leaq 1(%r9), %rdi 
.67799: cmpq $9, %r9 
.67803: je .67974 
.67809: xorl %ecx, %ecx 
.67811: jmp .67544 
.67816: movq %r14, %rax 
.67819: movb $0x30, -1(%r8) 
.67824: notq %rax 
.67827: addq %rax, %r8 
.67830: movl %r14d, %eax 
.67833: cmpl $8, %r14d 
.67837: jae .67896 
.67839: andl $4, %r14d 
.67843: jne .68010 
.67849: testl %eax, %eax 
.67851: je .67428 
.67857: movzbl (%r15), %edx 
.67861: movb %dl, (%r8) 
.67864: testb $2, %al 
.67866: je .67428 
.67872: movzwl -2(%r15, %rax), %edx 
.67878: movw %dx, -2(%r8, %rax) 
.67884: jmp .67428 
.67896: movq (%r15), %rax 
.67899: leaq 8(%r8), %rcx 
.67903: andq $0xfffffffffffffff8, %rcx 
.67907: movq %rax, (%r8) 
.67910: movl %r14d, %eax 
.67913: movq -8(%r15, %rax), %rdx 
.67918: movq %rdx, -8(%r8, %rax) 
.67923: movq %r8, %rax 
.67926: subq %rcx, %rax 
.67929: subq %rax, %r15 
.67932: addl %r14d, %eax 
.67935: andl $0xfffffff8, %eax 
.67938: cmpl $8, %eax 
.67941: jb .67428 
.67947: andl $0xfffffff8, %eax 
.67950: xorl %edx, %edx 
.67952: movl %edx, %esi 
.67954: addl $8, %edx 
.67957: movq (%r15, %rsi), %rdi 
.67961: movq %rdi, (%rcx, %rsi) 
.67965: cmpl %eax, %edx 
.67967: jb .67952 
.67969: jmp .67428 
.67974: movq 8(%rsp), %r8 
.67979: jmp .67614 
.67984: movl (%r15), %eax 
.67987: movl %eax, (%r8) 
.67990: movl -4(%r15, %r9), %eax 
.67995: movl %eax, -4(%r8, %r9) 
.68000: jmp .67614 
.68005: hlt 
.68010: movl (%r15), %edx 
.68013: movl %edx, (%r8) 
.68016: movl -4(%r15, %rax), %edx 
.68021: movl %edx, -4(%r8, %rax) 
.68026: jmp .67428 
.68031: addl $0x30, %eax 
.68034: jmp .67561 
.68039: movq 8(%rsp), %rdx 
.68044: testl %eax, %eax 
.68046: jne .67198 
.68052: jmp .66647 
