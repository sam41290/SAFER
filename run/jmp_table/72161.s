.72161: nopw %cs:(%rax, %rax) 
.72172: nopl (%rax) 
.72176: pushq %r15 
.72178: movq %rdi, %r10 
.72181: pushq %r14 
.72183: movq %rcx, %r14 
.72186: pushq %r13 
.72188: pushq %r12 
.72190: pushq %rbp 
.72191: pushq %rbx 
.72192: movq %rdx, %rbx 
.72195: subq $0x4c8, %rsp 
.72202: movq 0x30(%rcx), %r15 
.72206: movl 8(%rcx), %r13d 
.72210: movq 0x500(%rsp), %rax 
.72218: movq %rsi, (%rsp) 
.72222: movq %r9, 0x18(%rsp) 
.72227: movq %rax, 0x10(%rsp) 
.72232: movb %r8b, 0x2b(%rsp) 
.72237: movq %fs:0x28, %rax 
.72246: movq %rax, 0x4b8(%rsp) 
.72254: xorl %eax, %eax 
.72256: testq %r15, %r15 
.72259: leaq .104446(%rip), %rax 
.72266: cmoveq %rax, %r15 
.72270: cmpl $0xc, %r13d 
.72274: jle .72448 
.72280: subl $0xc, %r13d 
.72284: movzbl (%rbx), %eax 
.72287: xorl %r11d, %r11d 
.72290: testb %al, %al 
.72292: je .72375 
.72294: movl %r13d, 0x2c(%rsp) 
.72299: movq %r11, %rbp 
.72302: movq %r10, %r12 
.72305: movq %r15, 0x20(%rsp) 
.72310: movq %r14, 8(%rsp) 
.72315: cmpb $0x25, %al 
.72317: je .72472 
.72323: movq (%rsp), %rdx 
.72327: subq %rbp, %rdx 
.72330: cmpq $1, %rdx 
.72334: jbe .72400 
.72336: testq %r12, %r12 
.72339: je .72349 
.72341: movb %al, (%r12) 
.72345: addq $1, %r12 
.72349: addq $1, %rbp 
.72353: movq %rbx, %r8 
.72356: movzbl 1(%r8), %eax 
.72361: leaq 1(%r8), %rbx 
.72365: testb %al, %al 
.72367: jne .72315 
.72369: movq %rbp, %r11 
.72372: movq %r12, %r10 
.72375: testq %r10, %r10 
.72378: je .72403 
.72380: cmpq $0, (%rsp) 
.72385: je .72403 
.72387: movb $0, (%r10) 
.72391: jmp .72403 
.72400: xorl %r11d, %r11d 
.72403: movq 0x4b8(%rsp), %rax 
.72411: xorq %fs:0x28, %rax 
.72420: jne .78422 
.72426: addq $0x4c8, %rsp 
.72433: movq %r11, %rax 
.72436: popq %rbx 
.72437: popq %rbp 
.72438: popq %r12 
.72440: popq %r13 
.72442: popq %r14 
.72444: popq %r15 
.72446: ret 
.72448: testl %r13d, %r13d 
.72451: movl $0xc, %eax 
.72456: cmovel %eax, %r13d 
.72460: jmp .72284 
.72472: movzbl 0x2b(%rsp), %r10d 
.72478: xorl %r8d, %r8d 
.72481: xorl %r14d, %r14d 
.72484: nopl (%rax) 
.72488: movsbl 1(%rbx), %r9d 
.72493: addq $1, %rbx 
.72497: movl %r9d, %ecx 
.72500: cmpb $0x30, %r9b 
.72504: je .72880 
.72510: jg .72528 
.72512: cmpb $0x23, %r9b 
.72516: jne .72544 
.72518: movl $1, %r8d 
.72524: jmp .72488 
.72528: cmpb $0x5e, %r9b 
.72532: jne .72560 
.72534: movl $1, %r10d 
.72540: jmp .72488 
.72544: cmpb $0x2d, %r9b 
.72548: jne .72584 
.72550: movl $0x2d, %r14d 
.72556: jmp .72488 
.72560: cmpb $0x5f, %r9b 
.72564: jne .72896 
.72570: movl $0x5f, %r14d 
.72576: jmp .72488 
.72584: movl $0xffffffff, %r13d 
.72590: cmpb $0x4f, %cl 
.72593: je .72637 
.72595: xorl %r9d, %r9d 
.72598: cmpb $0x7a, %cl 
.72601: ja .72656 
.72603: leaq .114716(%rip), %rdi 
.72610: movzbl %cl, %eax 
.72613: movslq (%rdi, %rax, 4), %rax 
.72617: addq %rdi, %rax 
.72620: jmpq *%rax 
.72623: orl $0xffffffff, %r13d 
.72627: nopl (%rax, %rax) 
.72632: cmpb $0x45, %cl 
.72635: jne .72590 
.72637: movzbl 1(%rbx), %ecx 
.72641: addq $1, %rbx 
.72645: cmpb $0x7a, %cl 
.72648: jbe .72603 
.72650: nopw (%rax, %rax) 
.72656: leaq -1(%rbx), %rax 
.72660: leal 1(%rbx), %edx 
.72663: movq %rax, %r9 
.72666: movl %edx, %ecx 
.72668: subl %eax, %ecx 
.72670: cmpb $0x25, (%r9) 
.72674: leaq -1(%rax), %rax 
.72678: jne .72663 
.72680: movq (%rsp), %rdx 
.72684: movl $0, %eax 
.72689: movslq %ecx, %rcx 
.72692: movq %rbx, %r8 
.72695: movq %rcx, %r15 
.72698: subq %rbp, %rdx 
.72701: testl %r13d, %r13d 
.72704: cmovnsl %r13d, %eax 
.72708: cltq 
.72710: cmpq %rcx, %rax 
.72713: cmovaeq %rax, %r15 
.72717: cmpq %rdx, %r15 
.72720: jae .72400 
.72726: testq %r12, %r12 
.72729: je .72863 
.72735: cmpq %rax, %rcx 
.72738: jae .72817 
.72740: movslq %r13d, %rdx 
.72743: movq %rcx, 0x50(%rsp) 
.72748: subq %rcx, %rdx 
.72751: movq %r8, 0x48(%rsp) 
.72756: movq %r9, 0x40(%rsp) 
.72761: leaq (%r12, %rdx), %rbx 
.72765: movb %r10b, 0x30(%rsp) 
.72770: cmpl $0x30, %r14d 
.72774: je .77583 
.72780: movq %r12, %rdi 
.72783: movl $0x20, %esi 
.72788: movq %rbx, %r12 
.72791: callq .18912 
.72796: movq 0x50(%rsp), %rcx 
.72801: movq 0x48(%rsp), %r8 
.72806: movq 0x40(%rsp), %r9 
.72811: movzbl 0x30(%rsp), %r10d 
.72817: movq %r8, 0x40(%rsp) 
.72822: movq %rcx, %rdx 
.72825: movq %r9, %rsi 
.72828: movq %r12, %rdi 
.72831: movq %rcx, 0x30(%rsp) 
.72836: testb %r10b, %r10b 
.72839: je .77068 
.72845: callq .72096 
.72850: movq 0x30(%rsp), %rcx 
.72855: movq 0x40(%rsp), %r8 
.72860: addq %rcx, %r12 
.72863: addq %r15, %rbp 
.72866: jmp .72356 
.72880: movl $0x30, %r14d 
.72886: jmp .72488 
.72896: leal -0x30(%r9), %eax 
.72900: cmpl $9, %eax 
.72903: ja .72623 
.72909: xorl %r13d, %r13d 
.72912: movsbl 1(%rbx), %r9d 
.72917: leaq 1(%rbx), %rdx 
.72921: movl %r9d, %ecx 
.72924: leal -0x30(%r9), %eax 
.72928: cmpl $0xccccccc, %r13d 
.72935: jg .72974 
.72937: movsbl (%rbx), %esi 
.72940: je .72968 
.72942: leal (%r13, %r13, 4), %edi 
.72947: movq %rdx, %rbx 
.72950: leal -0x30(%rsi, %rdi, 2), %r13d 
.72955: cmpl $9, %eax 
.72958: jbe .72912 
.72960: jmp .72632 
.72968: cmpb $0x37, %sil 
.72972: jle .72942 
.72974: cmpl $9, %eax 
.72977: ja .73008 
.72979: movsbl 2(%rbx), %r9d 
.72984: movl $0x7fffffff, %r13d 
.72990: addq $2, %rbx 
.72994: movl %r9d, %ecx 
.72997: leal -0x30(%r9), %eax 
.73001: jmp .72955 
.73008: movq %rdx, %rbx 
.73011: movl $0x7fffffff, %r13d 
.73017: jmp .72632 
.73022: cmpl $0x4f, %r9d 
.73026: je .72656 
.73032: xorl %r15d, %r15d 
.73035: movl $0x2520, %edi 
.73040: movw %di, 0xab(%rsp) 
.73048: testl %r9d, %r9d 
.73051: jne .78447 
.73057: movq %rbx, %r8 
.73060: leaq 0xad(%rsp), %rax 
.73068: movb %cl, (%rax) 
.73070: movq 8(%rsp), %rcx 
.73075: leaq 0xab(%rsp), %rdx 
.73083: leaq 0xb0(%rsp), %rdi 
.73091: movb $0, 1(%rax) 
.73095: movl $0x400, %esi 
.73100: movq %r8, 0x30(%rsp) 
.73105: movl %r9d, 0x48(%rsp) 
.73110: movb %r10b, 0x40(%rsp) 
.73115: callq .19504 
.73120: movq 0x30(%rsp), %r8 
.73125: testq %rax, %rax 
.73128: je .72356 
.73134: leaq -1(%rax), %rcx 
.73138: testl %r13d, %r13d 
.73141: movl $0, %eax 
.73146: movq (%rsp), %rdx 
.73150: cmovnsl %r13d, %eax 
.73154: cltq 
.73156: cmpq %rax, %rcx 
.73159: movq %rax, %rbx 
.73162: cmovaeq %rcx, %rbx 
.73166: subq %rbp, %rdx 
.73169: cmpq %rbx, %rdx 
.73172: jbe .72400 
.73178: testq %r12, %r12 
.73181: je .73335 
.73187: movl 0x48(%rsp), %r9d 
.73192: movzbl 0x40(%rsp), %r10d 
.73198: testl %r9d, %r9d 
.73201: jne .73275 
.73203: cmpq %rax, %rcx 
.73206: jae .73275 
.73208: movslq %r13d, %rdx 
.73211: movq %rcx, 0x48(%rsp) 
.73216: subq %rcx, %rdx 
.73219: movq %r8, 0x40(%rsp) 
.73224: movb %r10b, 0x30(%rsp) 
.73229: leaq (%r12, %rdx), %r13 
.73233: cmpl $0x30, %r14d 
.73237: je .77128 
.73243: movq %r12, %rdi 
.73246: movl $0x20, %esi 
.73251: movq %r13, %r12 
.73254: callq .18912 
.73259: movq 0x48(%rsp), %rcx 
.73264: movq 0x40(%rsp), %r8 
.73269: movzbl 0x30(%rsp), %r10d 
.73275: movq %r8, 0x40(%rsp) 
.73280: leaq 0xb1(%rsp), %rsi 
.73288: movq %rcx, %rdx 
.73291: movq %r12, %rdi 
.73294: movq %rcx, 0x30(%rsp) 
.73299: testb %r15b, %r15b 
.73302: jne .77108 
.73308: testb %r10b, %r10b 
.73311: je .77088 
.73317: callq .72096 
.73322: movq 0x30(%rsp), %rcx 
.73327: movq 0x40(%rsp), %r8 
.73332: addq %rcx, %r12 
.73335: addq %rbx, %rbp 
.73338: jmp .72356 
.73343: cmpl $0x45, %r9d 
.73347: je .72656 
.73353: movq 8(%rsp), %rsi 
.73358: movl 0x14(%rsi), %r8d 
.73362: movl 0x1c(%rsi), %edi 
.73365: movl 0x18(%rsi), %r15d 
.73369: movl %r8d, %eax 
.73372: movl %edi, %edx 
.73374: sarl $0x1f, %eax 
.73377: subl %r15d, %edx 
.73380: andl $0x190, %eax 
.73385: addl $0x17e, %edx 
.73391: leal -0x64(%r8, %rax), %eax 
.73396: movl %edx, %esi 
.73398: movl %eax, 0x30(%rsp) 
.73402: movslq %edx, %rax 
.73405: sarl $0x1f, %esi 
.73408: imulq $-0x6db6db6d, %rax, %rax 
.73415: shrq $0x20, %rax 
.73419: addl %edx, %eax 
.73421: sarl $2, %eax 
.73424: subl %esi, %eax 
.73426: leal (, %rax, 8), %esi 
.73433: subl %eax, %esi 
.73435: movl %edi, %eax 
.73437: subl %edx, %eax 
.73439: leal 3(%rax, %rsi), %r11d 
.73444: testl %r11d, %r11d 
.73447: js .77834 
.73453: movl 0x30(%rsp), %eax 
.73457: movl $0x16d, %edx 
.73462: testb $3, %al 
.73464: jne .73514 
.73466: imull $0xc28f5c29, %eax, %eax 
.73472: movl $0x16e, %edx 
.73477: addl $0x51eb850, %eax 
.73482: movl %eax, %esi 
.73484: rorl $2, %esi 
.73487: cmpl $0x28f5c28, %esi 
.73493: ja .73514 
.73495: rorl $4, %eax 
.73498: xorl %edx, %edx 
.73500: cmpl $0xa3d70b, %eax 
.73505: setb %dl 
.73508: addl $0x16d, %edx 
.73514: movl %edi, %esi 
.73516: subl %edx, %esi 
.73518: movl %esi, %edx 
.73520: subl %r15d, %edx 
.73523: addl $0x17e, %edx 
.73529: movslq %edx, %rax 
.73532: movl %edx, %edi 
.73534: subl %edx, %esi 
.73536: imulq $-0x6db6db6d, %rax, %rax 
.73543: sarl $0x1f, %edi 
.73546: shrq $0x20, %rax 
.73550: addl %edx, %eax 
.73552: sarl $2, %eax 
.73555: subl %edi, %eax 
.73557: leal (, %rax, 8), %edi 
.73564: subl %eax, %edi 
.73566: leal 3(%rsi, %rdi), %r15d 
.73571: testl %r15d, %r15d 
.73574: cmovnsl %r15d, %r11d 
.73578: sarl $0x1f, %r15d 
.73582: addl $1, %r15d 
.73586: cmpb $0x47, %cl 
.73589: je .78077 
.73595: cmpb $0x67, %cl 
.73598: jne .78037 
.73604: movslq %r8d, %rax 
.73607: movl %r8d, %edx 
.73610: movl %r8d, %esi 
.73613: movl $2, %edi 
.73618: imulq $0x51eb851f, %rax, %rax 
.73625: sarl $0x1f, %edx 
.73628: sarq $0x25, %rax 
.73632: subl %edx, %eax 
.73634: imull $0x64, %eax, %eax 
.73637: subl %eax, %esi 
.73639: movl %esi, %eax 
.73641: addl %r15d, %eax 
.73644: movslq %eax, %rdx 
.73647: movl %eax, %esi 
.73649: imulq $0x51eb851f, %rdx, %rdx 
.73656: sarl $0x1f, %esi 
.73659: sarq $0x25, %rdx 
.73663: subl %esi, %edx 
.73665: imull $0x64, %edx, %edx 
.73668: subl %edx, %eax 
.73670: movl %eax, %edx 
.73672: jns .73696 
.73674: movl $0xfffff894, %eax 
.73679: movl %edx, %esi 
.73681: addl $0x64, %edx 
.73684: subl %r15d, %eax 
.73687: negl %esi 
.73689: cmpl %eax, %r8d 
.73692: cmovll %esi, %edx 
.73695: nop 
.73696: movl %edx, %eax 
.73698: xorl %esi, %esi 
.73700: xorl %r8d, %r8d 
.73703: shrl $0x1f, %eax 
.73706: movl %eax, 0x30(%rsp) 
.73710: cmpl $0x4f, %r9d 
.73714: jne .73904 
.73720: cmpb $0, 0x30(%rsp) 
.73725: jne .73911 
.73731: movl $0x2520, %eax 
.73736: xorl %r15d, %r15d 
.73739: movw %ax, 0xab(%rsp) 
.73747: movb %r9b, 0xad(%rsp) 
.73755: movq %rbx, %r8 
.73758: movl %edi, %r9d 
.73761: leaq 0xae(%rsp), %rax 
.73769: jmp .73068 
.73774: testl %r9d, %r9d 
.73777: jne .72656 
.73783: testb %r8b, %r8b 
.73786: movl $0x2520, %edx 
.73791: leaq 0xad(%rsp), %rax 
.73799: cmovnel %r8d, %r10d 
.73803: movq %rbx, %r8 
.73806: xorl %r15d, %r15d 
.73809: xorl %r9d, %r9d 
.73812: movw %dx, 0xab(%rsp) 
.73820: jmp .73068 
.73825: testb %r8b, %r8b 
.73828: cmovnel %r8d, %r10d 
.73832: cmpl $0x45, %r9d 
.73836: jne .73032 
.73842: jmp .72656 
.73847: cmpl $0x45, %r9d 
.73851: je .77576 
.73857: cmpl $0x4f, %r9d 
.73861: je .72656 
.73867: movq 8(%rsp), %rax 
.73872: movl $4, %edi 
.73877: movl 0x14(%rax), %edx 
.73880: cmpl $0xfffff894, %edx 
.73886: setl 0x30(%rsp) 
.73891: addl $0x76c, %edx 
.73897: xorl %esi, %esi 
.73899: xorl %r8d, %r8d 
.73902: nop 
.73904: cmpb $0, 0x30(%rsp) 
.73909: je .73913 
.73911: negl %edx 
.73913: leaq 0xc7(%rsp), %rax 
.73921: movl %edi, 0x48(%rsp) 
.73925: movl $0xcccccccd, %r11d 
.73931: movq %rax, %r15 
.73934: movq %rax, 0x40(%rsp) 
.73939: leaq -1(%r15), %r9 
.73943: testb $1, %sil 
.73947: je .74012 
.73949: nopl (%rax) 
.73952: movb $0x3a, -1(%r15) 
.73957: subq $2, %r15 
.73961: movl %edx, %eax 
.73963: movl %edx, %edi 
.73965: sarl $1, %esi 
.73967: imulq %r11, %rax 
.73971: shrq $0x23, %rax 
.73975: leal (%rax, %rax, 4), %ecx 
.73978: addl %ecx, %ecx 
.73980: subl %ecx, %edi 
.73982: movl %edi, %ecx 
.73984: addl $0x30, %ecx 
.73987: movb %cl, -1(%r9) 
.73991: cmpl $9, %edx 
.73994: ja .74000 
.73996: testl %esi, %esi 
.73998: je .74032 
.74000: movl %eax, %edx 
.74002: leaq -1(%r15), %r9 
.74006: testb $1, %sil 
.74010: jne .73952 
.74012: movq %r9, %rax 
.74015: movq %r15, %r9 
.74018: movq %rax, %r15 
.74021: jmp .73961 
.74032: endbr64 
.74036: movl 0x48(%rsp), %edi 
.74040: cmpl %r13d, %edi 
.74043: cmovll %r13d, %edi 
.74047: cmpb $0, 0x30(%rsp) 
.74052: movl %edi, %r11d 
.74055: jne .76848 
.74061: testb %r8b, %r8b 
.74064: je .75055 
.74070: cmpl $0x2d, %r14d 
.74074: je .77625 
.74080: movb $0x2b, 0x30(%rsp) 
.74085: movq 0x40(%rsp), %r9 
.74090: movq (%rsp), %rax 
.74094: leal -1(%r11), %ecx 
.74098: subq %r15, %r9 
.74101: subq %rbp, %rax 
.74104: subl %r9d, %ecx 
.74107: testl %ecx, %ecx 
.74109: jle .77165 
.74115: cmpl $0x5f, %r14d 
.74119: je .77345 
.74125: movslq %r11d, %rdx 
.74128: cmpq %rax, %rdx 
.74131: jae .72400 
.74137: cmpb $0, 0x30(%rsp) 
.74142: je .77469 
.74148: testl %r13d, %r13d 
.74151: movl $0, %edx 
.74156: movl $1, %esi 
.74161: cmovnsl %r13d, %edx 
.74165: movslq %edx, %rdx 
.74168: testq %rdx, %rdx 
.74171: cmovneq %rdx, %rsi 
.74175: cmpq %rax, %rsi 
.74178: jae .72400 
.74184: movslq %ecx, %rcx 
.74187: addq %rsi, %rbp 
.74190: testq %r12, %r12 
.74193: je .74342 
.74199: testl %r11d, %r11d 
.74202: jne .74278 
.74204: cmpq $1, %rdx 
.74208: jbe .74278 
.74210: movslq %r13d, %rdx 
.74213: movq %rcx, 0x58(%rsp) 
.74218: subq $1, %rdx 
.74222: movl %r11d, 0x50(%rsp) 
.74227: movb %r10b, 0x48(%rsp) 
.74232: leaq (%r12, %rdx), %r13 
.74236: cmpl $0x30, %r14d 
.74240: je .78361 
.74246: movq %r12, %rdi 
.74249: movl $0x20, %esi 
.74254: movq %r13, %r12 
.74257: callq .18912 
.74262: movq 0x58(%rsp), %rcx 
.74267: movl 0x50(%rsp), %r11d 
.74272: movzbl 0x48(%rsp), %r10d 
.74278: movzbl 0x30(%rsp), %eax 
.74283: addq $1, %r12 
.74287: movb %al, -1(%r12) 
.74292: movq %rcx, %rdx 
.74295: movq %r12, %rdi 
.74298: movl $0x30, %esi 
.74303: movl %r11d, 0x50(%rsp) 
.74308: movb %r10b, 0x48(%rsp) 
.74313: movq %rcx, 0x30(%rsp) 
.74318: callq .18912 
.74323: movq 0x30(%rsp), %rcx 
.74328: movl 0x50(%rsp), %r11d 
.74333: movzbl 0x48(%rsp), %r10d 
.74339: addq %rcx, %r12 
.74342: movq 0x40(%rsp), %r9 
.74347: movq (%rsp), %rax 
.74351: addq %rcx, %rbp 
.74354: movq %rbx, %r8 
.74357: xorl %ecx, %ecx 
.74359: xorl %r13d, %r13d 
.74362: subq %r15, %r9 
.74365: subq %rbp, %rax 
.74368: cmpq %rcx, %r9 
.74371: movq %rcx, %rbx 
.74374: cmovaeq %r9, %rbx 
.74378: cmpq %rax, %rbx 
.74381: jae .72400 
.74387: testq %r12, %r12 
.74390: je .73335 
.74396: testl %r11d, %r11d 
.74399: jne .74473 
.74401: cmpq %rcx, %r9 
.74404: jae .74473 
.74406: movslq %r13d, %rdx 
.74409: movq %r9, 0x48(%rsp) 
.74414: subq %r9, %rdx 
.74417: movq %r8, 0x40(%rsp) 
.74422: movb %r10b, 0x30(%rsp) 
.74427: leaq (%r12, %rdx), %r13 
.74431: cmpl $0x30, %r14d 
.74435: je .77486 
.74441: movq %r12, %rdi 
.74444: movl $0x20, %esi 
.74449: movq %r13, %r12 
.74452: callq .18912 
.74457: movq 0x48(%rsp), %r9 
.74462: movq 0x40(%rsp), %r8 
.74467: movzbl 0x30(%rsp), %r10d 
.74473: movq %r8, 0x40(%rsp) 
.74478: movq %r9, %rdx 
.74481: movq %r15, %rsi 
.74484: movq %r12, %rdi 
.74487: movq %r9, 0x30(%rsp) 
.74492: testb %r10b, %r10b 
.74495: je .77048 
.74501: callq .72096 
.74506: movq 0x30(%rsp), %r9 
.74511: movq 0x40(%rsp), %r8 
.74516: addq %r9, %r12 
.74519: jmp .73335 
.74524: cmpl $0x45, %r9d 
.74528: je .72656 
.74534: cmpl $-1, %r13d 
.74538: jne .77973 
.74544: movl 0x508(%rsp), %edx 
.74551: movl $9, %r13d 
.74557: movl $9, %edi 
.74562: jmp .73696 
.74567: cmpl $0x45, %r9d 
.74571: je .72656 
.74577: movq 8(%rsp), %rax 
.74582: movl $2, %edi 
.74587: movl (%rax), %edx 
.74589: jmp .73696 
.74594: testl %r13d, %r13d 
.74597: movl $0, %r15d 
.74603: movl $1, %eax 
.74608: cmovnsl %r13d, %r15d 
.74612: movslq %r15d, %r15 
.74615: testq %r15, %r15 
.74618: cmoveq %rax, %r15 
.74622: movq (%rsp), %rax 
.74626: subq %rbp, %rax 
.74629: cmpq %r15, %rax 
.74632: jbe .72400 
.74638: testq %r12, %r12 
.74641: je .74695 
.74643: cmpl $1, %r13d 
.74647: jle .74686 
.74649: movslq %r13d, %rdx 
.74652: subq $1, %rdx 
.74656: leaq (%r12, %rdx), %r13 
.74660: cmpl $0x30, %r14d 
.74664: je .78307 
.74670: movq %r12, %rdi 
.74673: movl $0x20, %esi 
.74678: movq %r13, %r12 
.74681: callq .18912 
.74686: movb $9, (%r12) 
.74691: addq $1, %r12 
.74695: addq %r15, %rbp 
.74698: movq %rbx, %r8 
.74701: jmp .72356 
.74706: movq 8(%rsp), %rax 
.74711: movl $1, %edi 
.74716: movl 0x18(%rax), %eax 
.74719: leal 6(%rax), %edx 
.74722: movl %eax, 0x30(%rsp) 
.74726: movslq %edx, %rax 
.74729: movl %edx, %esi 
.74731: imulq $-0x6db6db6d, %rax, %rax 
.74738: sarl $0x1f, %esi 
.74741: shrq $0x20, %rax 
.74745: addl %edx, %eax 
.74747: sarl $2, %eax 
.74750: subl %esi, %eax 
.74752: leal (, %rax, 8), %esi 
.74759: subl %eax, %esi 
.74761: subl %esi, %edx 
.74763: addl $1, %edx 
.74766: jmp .73696 
.74771: cmpl $0x45, %r9d 
.74775: je .72656 
.74781: movq 8(%rsp), %rax 
.74786: movl $1, %edi 
.74791: movl 0x18(%rax), %edx 
.74794: jmp .73696 
.74799: movq 8(%rsp), %rax 
.74804: movl $1, %edi 
.74809: movl 0x10(%rax), %eax 
.74812: cmpl $0x4f, %r9d 
.74816: je .73731 
.74822: leal (%rax, %rax, 4), %edx 
.74825: movb $0, 0x30(%rsp) 
.74830: xorl %r8d, %r8d 
.74833: xorl %esi, %esi 
.74835: leal (%rax, %rdx, 2), %edx 
.74838: sarl $5, %edx 
.74841: addl $1, %edx 
.74844: jmp .73913 
.74849: movq 8(%rsp), %rax 
.74854: movq 0x10(%rsp), %rdi 
.74859: leaq 0x70(%rsp), %rsi 
.74864: movb %r10b, 0x48(%rsp) 
.74869: movdqu 0x20(%rax), %xmm4 
.74874: movdqu (%rax), %xmm0 
.74878: movdqu 0x10(%rax), %xmm2 
.74883: movq 0x30(%rax), %rax 
.74887: movaps %xmm0, 0x70(%rsp) 
.74892: movq %rax, 0xa0(%rsp) 
.74900: movaps %xmm2, 0x80(%rsp) 
.74908: movaps %xmm4, 0x30(%rsp) 
.74913: movaps %xmm4, 0x90(%rsp) 
.74921: callq .94432 
.74926: movzbl 0x48(%rsp), %r10d 
.74932: movl $0x30, %edi 
.74937: movq %rax, %rsi 
.74940: movq %rax, %rcx 
.74943: leaq 0xc7(%rsp), %rax 
.74951: movq %rax, 0x40(%rsp) 
.74956: movq %rax, %r15 
.74959: nop 
.74960: movabsq $0x6666666666666667, %rax 
.74970: imulq %rcx 
.74973: movq %rcx, %rax 
.74976: sarq $0x3f, %rax 
.74980: sarq $2, %rdx 
.74984: subq %rax, %rdx 
.74987: movq %rdx, %rax 
.74990: leaq (%rdx, %rdx, 4), %rdx 
.74994: addq %rdx, %rdx 
.74997: subq %rdx, %rcx 
.75000: movq %rcx, %rdx 
.75003: movq %rax, %rcx 
.75006: movl %edi, %eax 
.75008: subl %edx, %eax 
.75010: addl $0x30, %edx 
.75013: testq %rsi, %rsi 
.75016: cmovsl %eax, %edx 
.75019: subq $1, %r15 
.75023: movb %dl, (%r15) 
.75026: testq %rcx, %rcx 
.75029: jne .74960 
.75031: testl %r13d, %r13d 
.75034: movl $1, %edi 
.75039: cmovgl %r13d, %edi 
.75043: movl %edi, %r11d 
.75046: testq %rsi, %rsi 
.75049: js .76848 
.75055: movq 0x40(%rsp), %r9 
.75060: movq (%rsp), %rax 
.75064: subq %r15, %r9 
.75067: subq %rbp, %rax 
.75070: cmpl $0x2d, %r14d 
.75074: je .75090 
.75076: movl %r11d, %ecx 
.75079: subl %r9d, %ecx 
.75082: testl %ecx, %ecx 
.75084: jg .78153 
.75090: testl %r13d, %r13d 
.75093: movl $0, %ecx 
.75098: movq %rbx, %r8 
.75101: cmovnsl %r13d, %ecx 
.75105: movslq %ecx, %rcx 
.75108: jmp .74368 
.75113: cmpl $0x45, %r9d 
.75117: je .77576 
.75123: movq 8(%rsp), %rax 
.75128: movl $2, %edi 
.75133: movslq 0x14(%rax), %rdx 
.75137: movq %rdx, %rax 
.75140: imulq $0x51eb851f, %rdx, %rdx 
.75147: movl %eax, %esi 
.75149: sarl $0x1f, %esi 
.75152: sarq $0x25, %rdx 
.75156: subl %esi, %edx 
.75158: movl %eax, %esi 
.75160: imull $0x64, %edx, %edx 
.75163: subl %edx, %esi 
.75165: movl %esi, %edx 
.75167: jns .73696 
.75173: negl %esi 
.75175: addl $0x64, %edx 
.75178: cmpl $0xfffff893, %eax 
.75183: cmovlel %esi, %edx 
.75186: jmp .73696 
.75191: cmpl $0x45, %r9d 
.75195: je .72656 
.75201: movq 8(%rsp), %rsi 
.75206: movl 0x1c(%rsi), %eax 
.75209: subl 0x18(%rsi), %eax 
.75212: addl $7, %eax 
.75215: movslq %eax, %rdx 
.75218: movl $2, %edi 
.75223: imulq $-0x6db6db6d, %rdx, %rdx 
.75230: shrq $0x20, %rdx 
.75234: addl %eax, %edx 
.75236: sarl $0x1f, %eax 
.75239: sarl $2, %edx 
.75242: subl %eax, %edx 
.75244: jmp .73696 
.75249: cmpl $0x45, %r9d 
.75253: je .72656 
.75259: movq 8(%rsp), %rdi 
.75264: movl 0x18(%rdi), %eax 
.75267: leal 6(%rax), %edx 
.75270: movl %eax, 0x30(%rsp) 
.75274: movslq %edx, %rax 
.75277: movl %edx, %esi 
.75279: imulq $-0x6db6db6d, %rax, %rax 
.75286: sarl $0x1f, %esi 
.75289: shrq $0x20, %rax 
.75293: addl %edx, %eax 
.75295: sarl $2, %eax 
.75298: subl %esi, %eax 
.75300: leal (, %rax, 8), %esi 
.75307: subl %eax, %esi 
.75309: movl %esi, %eax 
.75311: movl 0x1c(%rdi), %esi 
.75314: subl %edx, %eax 
.75316: leal 7(%rax, %rsi), %eax 
.75320: jmp .75215 
.75322: testb %r8b, %r8b 
.75325: movl $0, %eax 
.75330: movq 0x20(%rsp), %rdi 
.75335: movb %r8b, 0x48(%rsp) 
.75340: cmovnel %eax, %r10d 
.75344: movb %r10b, 0x40(%rsp) 
.75349: callq .18624 
.75354: testl %r13d, %r13d 
.75357: movq (%rsp), %rdx 
.75361: movq %rax, %r15 
.75364: movl $0, %eax 
.75369: cmovnsl %r13d, %eax 
.75373: cltq 
.75375: cmpq %rax, %r15 
.75378: movq %rax, %rsi 
.75381: cmovaeq %r15, %rsi 
.75385: subq %rbp, %rdx 
.75388: movq %rsi, 0x30(%rsp) 
.75393: cmpq %rsi, %rdx 
.75396: jbe .72400 
.75402: testq %r12, %r12 
.75405: je .75519 
.75407: cmpq %rax, %r15 
.75410: movzbl 0x40(%rsp), %r10d 
.75416: movzbl 0x48(%rsp), %r8d 
.75422: jae .75482 
.75424: movslq %r13d, %rdx 
.75427: subq %r15, %rdx 
.75430: leaq (%r12, %rdx), %r13 
.75434: cmpl $0x30, %r14d 
.75438: je .78328 
.75444: movq %r12, %rdi 
.75447: movl $0x20, %esi 
.75452: movb %r8b, 0x48(%rsp) 
.75457: movq %r13, %r12 
.75460: movb %r10b, 0x40(%rsp) 
.75465: callq .18912 
.75470: movzbl 0x48(%rsp), %r8d 
.75476: movzbl 0x40(%rsp), %r10d 
.75482: movq 0x20(%rsp), %rsi 
.75487: movq %r15, %rdx 
.75490: movq %r12, %rdi 
.75493: testb %r8b, %r8b 
.75496: jne .78163 
.75502: testb %r10b, %r10b 
.75505: je .78173 
.75511: callq .72096 
.75516: addq %r15, %r12 
.75519: addq 0x30(%rsp), %rbp 
.75524: movq %rbx, %r8 
.75527: jmp .72356 
.75532: cmpl $0x45, %r9d 
.75536: je .72656 
.75542: movl 0x2c(%rsp), %edx 
.75546: movl $2, %edi 
.75551: jmp .73696 
.75556: cmpl $0x45, %r9d 
.75560: je .72656 
.75566: movq 8(%rsp), %rax 
.75571: movl $2, %edi 
.75576: movl 4(%rax), %edx 
.75579: jmp .73696 
.75584: cmpl $0x45, %r9d 
.75588: je .72656 
.75594: testb %r8b, %r8b 
.75597: cmovnel %r8d, %r10d 
.75601: xorl %r15d, %r15d 
.75604: jmp .73035 
.75609: cmpl $0x45, %r9d 
.75613: je .77576 
.75619: movq 8(%rsp), %rax 
.75624: movslq 0x14(%rax), %rsi 
.75628: movq %rsi, %rax 
.75631: imulq $0x51eb851f, %rsi, %rsi 
.75638: cltd 
.75639: movl %eax, %edi 
.75641: sarq $0x25, %rsi 
.75645: subl %edx, %esi 
.75647: leal 0x13(%rsi), %edx 
.75650: imull $0x64, %esi, %esi 
.75653: subl %esi, %edi 
.75655: movl %edi, %esi 
.75657: shrl $0x1f, %esi 
.75660: testl %edx, %edx 
.75662: movl %esi, %edi 
.75664: setg %sil 
.75668: andl %edi, %esi 
.75670: cmpl $0xfffff894, %eax 
.75675: movl $2, %edi 
.75680: setl 0x30(%rsp) 
.75685: subl %esi, %edx 
.75687: xorl %r8d, %r8d 
.75690: xorl %esi, %esi 
.75692: jmp .73710 
.75697: testl %r9d, %r9d 
.75700: jne .72656 
.75706: leaq .114697(%rip), %rax 
.75713: movq %rax, 0x30(%rsp) 
.75718: movl 0x508(%rsp), %eax 
.75725: movzbl %r10b, %r8d 
.75729: xorl %edi, %edi 
.75731: movq $-1, %rsi 
.75738: pushq %rax 
.75739: pushq 0x18(%rsp) 
.75743: movq 0x28(%rsp), %r9 
.75748: movq 0x18(%rsp), %rcx 
.75753: movq 0x40(%rsp), %rdx 
.75758: movl %r8d, 0x50(%rsp) 
.75763: callq .72176 
.75768: testl %r13d, %r13d 
.75771: popq %r10 
.75773: popq %r11 
.75775: movq %rax, %r15 
.75778: movl $0, %eax 
.75783: movq (%rsp), %r11 
.75787: cmovnsl %r13d, %eax 
.75791: cltq 
.75793: cmpq %rax, %r15 
.75796: movq %rax, %r10 
.75799: cmovaeq %r15, %r10 
.75803: subq %rbp, %r11 
.75806: cmpq %r10, %r11 
.75809: jbe .72400 
.75815: testq %r12, %r12 
.75818: je .75955 
.75824: cmpq %rax, %r15 
.75827: movl 0x40(%rsp), %r8d 
.75832: jae .75900 
.75834: movslq %r13d, %rdx 
.75837: movq %r10, 0x50(%rsp) 
.75842: subq %r15, %rdx 
.75845: movq %r11, 0x48(%rsp) 
.75850: leaq (%r12, %rdx), %r13 
.75854: cmpl $0x30, %r14d 
.75858: je .77798 
.75864: movq %r12, %rdi 
.75867: movl $0x20, %esi 
.75872: movl %r8d, 0x40(%rsp) 
.75877: movq %r13, %r12 
.75880: callq .18912 
.75885: movq 0x50(%rsp), %r10 
.75890: movq 0x48(%rsp), %r11 
.75895: movl 0x40(%rsp), %r8d 
.75900: movl 0x508(%rsp), %eax 
.75907: movq %r10, 0x40(%rsp) 
.75912: movq %r12, %rdi 
.75915: movq %r11, %rsi 
.75918: addq %r15, %r12 
.75921: pushq %rax 
.75922: pushq 0x18(%rsp) 
.75926: movq 0x28(%rsp), %r9 
.75931: movq 0x18(%rsp), %rcx 
.75936: movq 0x40(%rsp), %rdx 
.75941: callq .72176 
.75946: popq %r8 
.75948: popq %r9 
.75950: movq 0x40(%rsp), %r10 
.75955: addq %r10, %rbp 
.75958: movq %rbx, %r8 
.75961: jmp .72356 
.75966: testl %r9d, %r9d 
.75969: jne .72656 
.75975: leaq .114706(%rip), %rax 
.75982: movq %rax, 0x30(%rsp) 
.75987: jmp .75718 
.75992: movzbl -1(%rbx), %ecx 
.75996: leaq -1(%rbx), %r9 
.76000: movq (%rsp), %rdx 
.76004: movl $0, %eax 
.76009: subq %rbp, %rdx 
.76012: testl %r13d, %r13d 
.76015: cmovnsl %r13d, %eax 
.76019: cltq 
.76021: cmpb $0x25, %cl 
.76024: jne .78439 
.76030: testq %rax, %rax 
.76033: movl $1, %r15d 
.76039: movq %r9, %r8 
.76042: movl $1, %ecx 
.76047: cmovneq %rax, %r15 
.76051: jmp .72717 
.76056: movq (%rsp), %rdx 
.76060: movl $0, %eax 
.76065: movl $1, %r15d 
.76071: subq %rbp, %rdx 
.76074: testl %r13d, %r13d 
.76077: cmovnsl %r13d, %eax 
.76081: cltq 
.76083: testq %rax, %rax 
.76086: cmovneq %rax, %r15 
.76090: testl %r9d, %r9d 
.76093: jne .78221 
.76099: cmpq %r15, %rdx 
.76102: jbe .72400 
.76108: testq %r12, %r12 
.76111: je .74695 
.76117: cmpl $1, %r13d 
.76121: jle .76163 
.76123: movslq %r13d, %rdx 
.76126: subq $1, %rdx 
.76130: leaq (%r12, %rdx), %r13 
.76134: cmpl $0x30, %r14d 
.76138: je .78398 
.76144: movq %r12, %rdi 
.76147: movl $0x20, %esi 
.76152: movq %r13, %r12 
.76155: callq .18912 
.76160: movzbl (%rbx), %ecx 
.76163: movb %cl, (%r12) 
.76167: addq $1, %r12 
.76171: jmp .74695 
.76176: cmpl $0x45, %r9d 
.76180: je .72656 
.76186: movq 8(%rsp), %rax 
.76191: movl $2, %edi 
.76196: movl 8(%rax), %edx 
.76199: jmp .73696 
.76204: cmpl $0x45, %r9d 
.76208: je .72656 
.76214: movq 8(%rsp), %rax 
.76219: movl $2, %edi 
.76224: movl 0xc(%rax), %edx 
.76227: jmp .73696 
.76232: cmpl $0x45, %r9d 
.76236: je .72656 
.76242: movq 8(%rsp), %rax 
.76247: movl 0xc(%rax), %edx 
.76250: movl $2, %edi 
.76255: cmpl $0x30, %r14d 
.76259: je .73696 
.76265: cmpl $0x2d, %r14d 
.76269: je .73696 
.76275: movl $0x5f, %r14d 
.76281: jmp .73696 
.76286: cmpl $0x45, %r9d 
.76290: je .72656 
.76296: movq 8(%rsp), %rax 
.76301: movl $3, %edi 
.76306: movl 0x1c(%rax), %edx 
.76309: cmpl $-1, %edx 
.76312: setl 0x30(%rsp) 
.76317: addl $1, %edx 
.76320: xorl %esi, %esi 
.76322: xorl %r8d, %r8d 
.76325: jmp .73710 
.76330: cmpl $0x45, %r9d 
.76334: je .72656 
.76340: movq 8(%rsp), %rax 
.76345: movl 8(%rax), %edx 
.76348: jmp .76250 
.76350: cmpl $0x45, %r9d 
.76354: je .72656 
.76360: movl 0x2c(%rsp), %edx 
.76364: jmp .76250 
.76366: cmpl $0x45, %r9d 
.76370: je .72656 
.76376: movq 8(%rsp), %rax 
.76381: movl $2, %edi 
.76386: movl 0x10(%rax), %edx 
.76389: cmpl $-1, %edx 
.76392: setl 0x30(%rsp) 
.76397: addl $1, %edx 
.76400: xorl %esi, %esi 
.76402: xorl %r8d, %r8d 
.76405: jmp .73710 
.76410: testl %r13d, %r13d 
.76413: movl $0, %r15d 
.76419: movl $1, %eax 
.76424: cmovnsl %r13d, %r15d 
.76428: movslq %r15d, %r15 
.76431: testq %r15, %r15 
.76434: cmoveq %rax, %r15 
.76438: movq (%rsp), %rax 
.76442: subq %rbp, %rax 
.76445: cmpq %r15, %rax 
.76448: jbe .72400 
.76454: testq %r12, %r12 
.76457: je .74695 
.76463: cmpl $1, %r13d 
.76467: jle .76506 
.76469: movslq %r13d, %rdx 
.76472: subq $1, %rdx 
.76476: leaq (%r12, %rdx), %r13 
.76480: cmpl $0x30, %r14d 
.76484: je .78237 
.76490: movq %r12, %rdi 
.76493: movl $0x20, %esi 
.76498: movq %r13, %r12 
.76501: callq .18912 
.76506: movb $0xa, (%r12) 
.76511: addq $1, %r12 
.76515: jmp .74695 
.76520: movzbl 1(%rbx), %eax 
.76524: leaq 1(%rbx), %r8 
.76528: movl $1, %r11d 
.76534: cmpb $0x3a, %al 
.76536: je .76817 
.76542: cmpb $0x7a, %al 
.76544: jne .72656 
.76550: movq 8(%rsp), %rax 
.76555: movl 0x20(%rax), %esi 
.76558: testl %esi, %esi 
.76560: js .72356 
.76566: movq 0x28(%rax), %rdi 
.76570: movb $1, 0x30(%rsp) 
.76575: testl %edi, %edi 
.76577: js .76599 
.76579: movb $0, 0x30(%rsp) 
.76584: jne .76599 
.76586: movq 0x20(%rsp), %rax 
.76591: cmpb $0x2d, (%rax) 
.76594: sete 0x30(%rsp) 
.76599: movslq %edi, %rax 
.76602: movl %edi, %esi 
.76604: imulq $-0x6e5d4c3b, %rax, %rdx 
.76611: sarl $0x1f, %esi 
.76614: imulq $-0x77777777, %rax, %rax 
.76621: shrq $0x20, %rdx 
.76625: shrq $0x20, %rax 
.76629: addl %edi, %edx 
.76631: addl %edi, %eax 
.76633: sarl $0xb, %edx 
.76636: sarl $5, %eax 
.76639: movl %edx, %ebx 
.76641: subl %esi, %eax 
.76643: subl %esi, %ebx 
.76645: movslq %eax, %rsi 
.76648: cltd 
.76649: imulq $-0x77777777, %rsi, %rsi 
.76656: shrq $0x20, %rsi 
.76660: addl %eax, %esi 
.76662: sarl $5, %esi 
.76665: subl %edx, %esi 
.76667: movl %eax, %edx 
.76669: imull $0x3c, %esi, %esi 
.76672: imull $0x3c, %eax, %eax 
.76675: subl %esi, %edx 
.76677: movl %edx, %esi 
.76679: subl %eax, %edi 
.76681: cmpq $2, %r11 
.76685: je .78116 
.76691: ja .77523 
.76697: testq %r11, %r11 
.76700: je .78183 
.76706: imull $0x64, %ebx, %edx 
.76709: movl $6, %edi 
.76714: movq %r8, %rbx 
.76717: movl $1, %r8d 
.76723: addl %esi, %edx 
.76725: movl $4, %esi 
.76730: jmp .73710 
.76735: movq %rbx, %r8 
.76738: xorl %r11d, %r11d 
.76741: jmp .76550 
.76746: xorl %r15d, %r15d 
.76749: testb %r8b, %r8b 
.76752: movl $0, %eax 
.76757: movl $0x70, %ecx 
.76762: cmovnel %r8d, %r15d 
.76766: cmovnel %eax, %r10d 
.76770: jmp .73035 
.76775: leaq .105127(%rip), %rax 
.76782: movq %rax, 0x30(%rsp) 
.76787: jmp .75718 
.76792: leaq .114688(%rip), %rax 
.76799: movq %rax, 0x30(%rsp) 
.76804: jmp .75718 
.76809: movl $1, %r15d 
.76815: jmp .76749 
.76817: addq $1, %r11 
.76821: movzbl (%rbx, %r11), %eax 
.76826: leaq (%rbx, %r11), %r8 
.76830: cmpb $0x3a, %al 
.76832: jne .76542 
.76838: jmp .76817 
.76848: movb $0x2d, 0x30(%rsp) 
.76853: movl $0x2d, %r8d 
.76859: cmpl $0x2d, %r14d 
.76863: jne .74085 
.76869: testl %r13d, %r13d 
.76872: movl $0, %ecx 
.76877: movq (%rsp), %rax 
.76881: movl $1, %r14d 
.76887: cmovnsl %r13d, %ecx 
.76891: movslq %ecx, %rcx 
.76894: testq %rcx, %rcx 
.76897: cmovneq %rcx, %r14 
.76901: subq %rbp, %rax 
.76904: cmpq %r14, %rax 
.76907: jbe .72400 
.76913: testq %r12, %r12 
.76916: je .77012 
.76918: testl %r11d, %r11d 
.76921: jne .77004 
.76923: cmpq $1, %rcx 
.76927: jbe .77004 
.76929: movslq %r13d, %rdx 
.76932: movq %r12, %rdi 
.76935: movl $0x20, %esi 
.76940: movq %rcx, 0x60(%rsp) 
.76945: subq $1, %rdx 
.76949: movb %r8b, 0x58(%rsp) 
.76954: movl %r11d, 0x50(%rsp) 
.76959: movb %r10b, 0x48(%rsp) 
.76964: movq %rdx, 0x30(%rsp) 
.76969: callq .18912 
.76974: movq 0x30(%rsp), %rdx 
.76979: movq 0x60(%rsp), %rcx 
.76984: movzbl 0x58(%rsp), %r8d 
.76990: movl 0x50(%rsp), %r11d 
.76995: movzbl 0x48(%rsp), %r10d 
.77001: addq %rdx, %r12 
.77004: movb %r8b, (%r12) 
.77008: addq $1, %r12 
.77012: movq 0x40(%rsp), %r9 
.77017: movq (%rsp), %rax 
.77021: addq %r14, %rbp 
.77024: movq %rbx, %r8 
.77027: movl $0x2d, %r14d 
.77033: subq %r15, %r9 
.77036: subq %rbp, %rax 
.77039: jmp .74368 
.77048: callq .19168 
.77053: movq 0x40(%rsp), %r8 
.77058: movq 0x30(%rsp), %r9 
.77063: jmp .74516 
.77068: callq .19168 
.77073: movq 0x40(%rsp), %r8 
.77078: movq 0x30(%rsp), %rcx 
.77083: jmp .72860 
.77088: callq .19168 
.77093: movq 0x40(%rsp), %r8 
.77098: movq 0x30(%rsp), %rcx 
.77103: jmp .73332 
.77108: callq .72016 
.77113: movq 0x30(%rsp), %rcx 
.77118: movq 0x40(%rsp), %r8 
.77123: jmp .73332 
.77128: movq %r12, %rdi 
.77131: movl $0x30, %esi 
.77136: movq %r13, %r12 
.77139: callq .18912 
.77144: movzbl 0x30(%rsp), %r10d 
.77150: movq 0x40(%rsp), %r8 
.77155: movq 0x48(%rsp), %rcx 
.77160: jmp .73275 
.77165: testl %r13d, %r13d 
.77168: movl $0, %ecx 
.77173: movl $1, %r8d 
.77179: cmovnsl %r13d, %ecx 
.77183: movslq %ecx, %rcx 
.77186: testq %rcx, %rcx 
.77189: cmovneq %rcx, %r8 
.77193: cmpq %rax, %r8 
.77196: jae .72400 
.77202: testq %r12, %r12 
.77205: je .77327 
.77207: testl %r11d, %r11d 
.77210: jne .77313 
.77212: cmpq $1, %rcx 
.77216: jbe .77313 
.77218: movslq %r13d, %rdx 
.77221: movq %r9, 0x68(%rsp) 
.77226: subq $1, %rdx 
.77230: movq %rcx, 0x60(%rsp) 
.77235: leaq (%r12, %rdx), %rax 
.77239: movq %r8, 0x58(%rsp) 
.77244: movq %rax, 0x40(%rsp) 
.77249: movl %r11d, 0x50(%rsp) 
.77254: movb %r10b, 0x48(%rsp) 
.77259: cmpl $0x30, %r14d 
.77263: je .78258 
.77269: movq %r12, %rdi 
.77272: movl $0x20, %esi 
.77277: callq .18912 
.77282: movq 0x40(%rsp), %r12 
.77287: movq 0x68(%rsp), %r9 
.77292: movq 0x60(%rsp), %rcx 
.77297: movq 0x58(%rsp), %r8 
.77302: movl 0x50(%rsp), %r11d 
.77307: movzbl 0x48(%rsp), %r10d 
.77313: movzbl 0x30(%rsp), %eax 
.77318: addq $1, %r12 
.77322: movb %al, -1(%r12) 
.77327: movq (%rsp), %rax 
.77331: addq %r8, %rbp 
.77334: movq %rbx, %r8 
.77337: subq %rbp, %rax 
.77340: jmp .74368 
.77345: movslq %ecx, %rdx 
.77348: cmpq %rax, %rdx 
.77351: jae .72400 
.77357: testq %r12, %r12 
.77360: je .77417 
.77362: movq %r12, %rdi 
.77365: movl $0x20, %esi 
.77370: movl %ecx, 0x60(%rsp) 
.77374: movl %r11d, 0x58(%rsp) 
.77379: movb %r10b, 0x50(%rsp) 
.77384: movq %rdx, 0x48(%rsp) 
.77389: callq .18912 
.77394: movq 0x48(%rsp), %rdx 
.77399: movl 0x60(%rsp), %ecx 
.77403: movl 0x58(%rsp), %r11d 
.77408: movzbl 0x50(%rsp), %r10d 
.77414: addq %rdx, %r12 
.77417: addq %rdx, %rbp 
.77420: cmpl %ecx, %r13d 
.77423: jle .77788 
.77429: subl %ecx, %r13d 
.77432: movslq %r13d, %rcx 
.77435: movq (%rsp), %rax 
.77439: subq %rbp, %rax 
.77442: cmpb $0, 0x30(%rsp) 
.77447: jne .77636 
.77453: movq 0x40(%rsp), %r9 
.77458: movq %rbx, %r8 
.77461: subq %r15, %r9 
.77464: jmp .74368 
.77469: movslq %ecx, %rcx 
.77472: testq %r12, %r12 
.77475: je .74342 
.77481: jmp .74292 
.77486: movq %r12, %rdi 
.77489: movl $0x30, %esi 
.77494: movq %r13, %r12 
.77497: callq .18912 
.77502: movzbl 0x30(%rsp), %r10d 
.77508: movq 0x40(%rsp), %r8 
.77513: movq 0x48(%rsp), %r9 
.77518: jmp .74473 
.77523: cmpq $3, %r11 
.77527: jne .78209 
.77533: testl %edi, %edi 
.77535: jne .78116 
.77541: testl %edx, %edx 
.77543: jne .76706 
.77549: movl %ebx, %edx 
.77551: movl $3, %edi 
.77556: movq %r8, %rbx 
.77559: movl $1, %r8d 
.77565: jmp .73710 
.77576: xorl %edi, %edi 
.77578: jmp .73731 
.77583: movq %r12, %rdi 
.77586: movl $0x30, %esi 
.77591: movq %rbx, %r12 
.77594: callq .18912 
.77599: movzbl 0x30(%rsp), %r10d 
.77605: movq 0x40(%rsp), %r9 
.77610: movq 0x48(%rsp), %r8 
.77615: movq 0x50(%rsp), %rcx 
.77620: jmp .72817 
.77625: movl $0x2b, %r8d 
.77631: jmp .76869 
.77636: testq %rcx, %rcx 
.77639: movl $1, %r8d 
.77645: cmovneq %rcx, %r8 
.77649: cmpq %rax, %r8 
.77652: jae .72400 
.77658: testq %r12, %r12 
.77661: je .77762 
.77663: testl %r11d, %r11d 
.77666: jne .77748 
.77668: cmpq $1, %rcx 
.77672: jbe .77748 
.77674: movslq %r13d, %rdx 
.77677: movq %r12, %rdi 
.77680: movl $0x20, %esi 
.77685: movq %rcx, 0x68(%rsp) 
.77690: subq $1, %rdx 
.77694: movq %r8, 0x60(%rsp) 
.77699: movl %r11d, 0x58(%rsp) 
.77704: movb %r10b, 0x50(%rsp) 
.77709: movq %rdx, 0x48(%rsp) 
.77714: callq .18912 
.77719: movq 0x48(%rsp), %rdx 
.77724: movq 0x68(%rsp), %rcx 
.77729: movq 0x60(%rsp), %r8 
.77734: movl 0x58(%rsp), %r11d 
.77739: movzbl 0x50(%rsp), %r10d 
.77745: addq %rdx, %r12 
.77748: movzbl 0x30(%rsp), %eax 
.77753: addq $1, %r12 
.77757: movb %al, -1(%r12) 
.77762: movq 0x40(%rsp), %r9 
.77767: movq (%rsp), %rax 
.77771: addq %r8, %rbp 
.77774: movq %rbx, %r8 
.77777: subq %r15, %r9 
.77780: subq %rbp, %rax 
.77783: jmp .74368 
.77788: xorl %ecx, %ecx 
.77790: xorl %r13d, %r13d 
.77793: jmp .77435 
.77798: movq %r12, %rdi 
.77801: movl $0x30, %esi 
.77806: movq %r13, %r12 
.77809: callq .18912 
.77814: movl 0x40(%rsp), %r8d 
.77819: movq 0x48(%rsp), %r11 
.77824: movq 0x50(%rsp), %r10 
.77829: jmp .75900 
.77834: movl 0x30(%rsp), %eax 
.77838: subl $1, %eax 
.77841: movl %eax, %r11d 
.77844: movl $0x16d, %eax 
.77849: testb $3, %r11b 
.77853: jne .77907 
.77855: imull $0xc28f5c29, %r11d, %edx 
.77862: movl $0x16e, %eax 
.77867: addl $0x51eb850, %edx 
.77873: rorl $2, %edx 
.77876: cmpl $0x28f5c28, %edx 
.77882: ja .77907 
.77884: movl %r11d, %eax 
.77887: movl $0x190, %esi 
.77892: cltd 
.77893: idivl %esi 
.77895: cmpl $1, %edx 
.77898: sbbl %eax, %eax 
.77900: notl %eax 
.77902: addl $0x16e, %eax 
.77907: addl %eax, %edi 
.77909: movl %edi, %edx 
.77911: subl %r15d, %edx 
.77914: movl $0xffffffff, %r15d 
.77920: addl $0x17e, %edx 
.77926: movslq %edx, %rax 
.77929: movl %edx, %esi 
.77931: subl %edx, %edi 
.77933: imulq $-0x6db6db6d, %rax, %rax 
.77940: sarl $0x1f, %esi 
.77943: shrq $0x20, %rax 
.77947: addl %edx, %eax 
.77949: sarl $2, %eax 
.77952: subl %esi, %eax 
.77954: leal (, %rax, 8), %esi 
.77961: subl %eax, %esi 
.77963: leal 3(%rdi, %rsi), %r11d 
.77968: jmp .73586 
.77973: cmpl $8, %r13d 
.77977: jg .78427 
.77983: movl 0x508(%rsp), %edx 
.77990: movl %r13d, %esi 
.77993: nopl (%rax) 
.78000: movslq %edx, %rax 
.78003: sarl $0x1f, %edx 
.78006: addl $1, %esi 
.78009: imulq $0x66666667, %rax, %rax 
.78016: sarq $0x22, %rax 
.78020: subl %edx, %eax 
.78022: movl %eax, %edx 
.78024: cmpl $9, %esi 
.78027: jne .78000 
.78029: movl %r13d, %edi 
.78032: jmp .73696 
.78037: movslq %r11d, %rdx 
.78040: movl $2, %edi 
.78045: imulq $-0x6db6db6d, %rdx, %rdx 
.78052: shrq $0x20, %rdx 
.78056: addl %r11d, %edx 
.78059: sarl $0x1f, %r11d 
.78063: sarl $2, %edx 
.78066: subl %r11d, %edx 
.78069: addl $1, %edx 
.78072: jmp .73696 
.78077: movl $0xfffff894, %eax 
.78082: leal 0x76c(%r8, %r15), %edx 
.78090: movl $4, %edi 
.78095: subl %r15d, %eax 
.78098: cmpl %eax, %r8d 
.78101: setl 0x30(%rsp) 
.78106: xorl %esi, %esi 
.78108: xorl %r8d, %r8d 
.78111: jmp .73710 
.78116: imull $0x2710, %ebx, %edx 
.78122: movq %r8, %rbx 
.78125: movl $1, %r8d 
.78131: imull $0x64, %esi, %esi 
.78134: addl %esi, %edx 
.78136: movl $0x14, %esi 
.78141: addl %edi, %edx 
.78143: movl $9, %edi 
.78148: jmp .73710 
.78153: movb $0, 0x30(%rsp) 
.78158: jmp .74115 
.78163: callq .72016 
.78168: jmp .75516 
.78173: callq .19168 
.78178: jmp .75516 
.78183: imull $0x64, %ebx, %edx 
.78186: movl $5, %edi 
.78191: movq %r8, %rbx 
.78194: movl $1, %r8d 
.78200: addl %esi, %edx 
.78202: xorl %esi, %esi 
.78204: jmp .73710 
.78209: movzbl (%r8), %ecx 
.78213: movq %r8, %r9 
.78216: jmp .76000 
.78221: movq %rbx, %r8 
.78224: movq %rbx, %r9 
.78227: movl $1, %ecx 
.78232: jmp .72717 
.78237: movq %r12, %rdi 
.78240: movl $0x30, %esi 
.78245: movq %r13, %r12 
.78248: callq .18912 
.78253: jmp .76506 
.78258: movq %r12, %rdi 
.78261: movl $0x30, %esi 
.78266: callq .18912 
.78271: movq 0x40(%rsp), %r12 
.78276: movzbl 0x48(%rsp), %r10d 
.78282: movl 0x50(%rsp), %r11d 
.78287: movq 0x58(%rsp), %r8 
.78292: movq 0x60(%rsp), %rcx 
.78297: movq 0x68(%rsp), %r9 
.78302: jmp .77313 
.78307: movq %r12, %rdi 
.78310: movl $0x30, %esi 
.78315: movq %r13, %r12 
.78318: callq .18912 
.78323: jmp .74686 
.78328: movq %r12, %rdi 
.78331: movl $0x30, %esi 
.78336: movq %r13, %r12 
.78339: callq .18912 
.78344: movzbl 0x40(%rsp), %r10d 
.78350: movzbl 0x48(%rsp), %r8d 
.78356: jmp .75482 
.78361: movq %r12, %rdi 
.78364: movl $0x30, %esi 
.78369: movq %r13, %r12 
.78372: callq .18912 
.78377: movzbl 0x48(%rsp), %r10d 
.78383: movl 0x50(%rsp), %r11d 
.78388: movq 0x58(%rsp), %rcx 
.78393: jmp .74278 
.78398: movq %r12, %rdi 
.78401: movl $0x30, %esi 
.78406: movq %r13, %r12 
.78409: callq .18912 
.78414: movzbl (%rbx), %ecx 
.78417: jmp .76163 
.78422: hlt 
.78427: movl 0x508(%rsp), %edx 
.78434: jmp .78029 
.78439: movq %r9, %rbx 
.78442: jmp .72656 
.78447: xorl %edi, %edi 
.78449: jmp .73747 
