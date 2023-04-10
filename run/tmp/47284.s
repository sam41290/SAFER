.47284: nopw %cs:(%rax, %rax) 
.47295: nop 
.47296: pushq %r15 
.47298: pushq %r14 
.47300: movq %rsi, %r14 
.47303: pushq %r13 
.47305: movq %rdi, %r13 
.47308: pushq %r12 
.47310: pushq %rbp 
.47311: pushq %rbx 
.47312: subq $0x358, %rsp 
.47319: movl %edx, 0x14(%rsp) 
.47323: movb %dl, 0x13(%rsp) 
.47327: movq %fs:0x28, %rax 
.47336: movq %rax, 0x348(%rsp) 
.47344: xorl %eax, %eax 
.47346: callq .18272 
.47351: movq %r13, %rdi 
.47354: movl $0, (%rax) 
.47360: movq %rax, %rbp 
.47363: callq .18544 
.47368: testq %rax, %rax 
.47371: je .48978 
.47377: cmpq $0, .148424(%rip) 
.47385: movq %rax, %r12 
.47388: je .47733 
.47394: movq %rax, %rdi 
.47397: callq .19104 
.47402: leaq 0x20(%rsp), %rdx 
.47407: movl %eax, %esi 
.47409: testl %eax, %eax 
.47411: js .48112 
.47417: movl $1, %edi 
.47422: callq .19344 
.47427: shrl $0x1f, %eax 
.47430: testb %al, %al 
.47432: jne .48136 
.47438: movq 0x28(%rsp), %rcx 
.47443: movq 0x20(%rsp), %rdx 
.47448: movl $0x10, %edi 
.47453: movq %rcx, 0x18(%rsp) 
.47458: movq %rdx, 8(%rsp) 
.47463: callq .88256 
.47468: movq 0x18(%rsp), %rcx 
.47473: movq 8(%rsp), %rdx 
.47478: movq .148424(%rip), %rdi 
.47485: movq %rax, %rsi 
.47488: movq %rax, %rbx 
.47491: movq %rcx, (%rax) 
.47494: movq %rdx, 8(%rax) 
.47498: callq .64416 
.47503: testq %rax, %rax 
.47506: je .49063 
.47512: cmpq %rax, %rbx 
.47515: je .47648 
.47521: movq %rbx, %rdi 
.47524: callq .18128 
.47529: movq %r13, %rdx 
.47532: movl $3, %esi 
.47537: xorl %edi, %edi 
.47539: callq .85600 
.47544: movl $5, %edx 
.47549: leaq .105896(%rip), %rsi 
.47556: xorl %edi, %edi 
.47558: movq %rax, %r13 
.47561: callq .18592 
.47566: movq %r13, %rcx 
.47569: xorl %esi, %esi 
.47571: xorl %edi, %edi 
.47573: movq %rax, %rdx 
.47576: xorl %eax, %eax 
.47578: callq .19552 
.47583: movq %r12, %rdi 
.47586: callq .18976 
.47591: movl $2, .147984(%rip) 
.47601: movq 0x348(%rsp), %rax 
.47609: xorq %fs:0x28, %rax 
.47618: jne .49068 
.47624: addq $0x358, %rsp 
.47631: popq %rbx 
.47632: popq %rbp 
.47633: popq %r12 
.47635: popq %r13 
.47637: popq %r14 
.47639: popq %r15 
.47641: ret 
.47648: movq .147704(%rip), %rax 
.47655: movq .147712(%rip), %rdx 
.47662: movq 0x28(%rsp), %rbx 
.47667: movq 0x20(%rsp), %rcx 
.47672: subq %rax, %rdx 
.47675: cmpq $0xf, %rdx 
.47679: ja .47715 
.47681: movl $0x10, %esi 
.47686: leaq .147680(%rip), %rdi 
.47693: movq %rcx, 8(%rsp) 
.47698: callq .92864 
.47703: movq .147704(%rip), %rax 
.47710: movq 8(%rsp), %rcx 
.47715: leaq 0x10(%rax), %rdx 
.47719: movq %rdx, .147704(%rip) 
.47726: movq %rcx, 8(%rax) 
.47730: movq %rbx, (%rax) 
.47733: callq .28528 
.47738: cmpb $0, .148214(%rip) 
.47745: je .48088 
.47751: cmpb $0, .143376(%rip) 
.47758: jne .47800 
.47760: movq .144008(%rip), %rdi 
.47767: movq 0x28(%rdi), %rax 
.47771: cmpq 0x30(%rdi), %rax 
.47775: jae .49018 
.47781: leaq 1(%rax), %rdx 
.47785: movq %rdx, 0x28(%rdi) 
.47789: movb $0xa, (%rax) 
.47792: addq $1, .147960(%rip) 
.47800: cmpb $0, .148248(%rip) 
.47807: movb $0, .143376(%rip) 
.47814: jne .48936 
.47820: xorl %ebx, %ebx 
.47822: cmpb $0, .148241(%rip) 
.47829: jne .48816 
.47835: testq %r14, %r14 
.47838: movq .148168(%rip), %rsi 
.47845: movl $0xffffffff, %edx 
.47850: leaq .147776(%rip), %r9 
.47857: cmoveq %r13, %r14 
.47861: subq $8, %rsp 
.47865: movl $1, %r8d 
.47871: xorl %ecx, %ecx 
.47873: pushq %rbx 
.47874: movq %r14, %rdi 
.47877: callq .34384 
.47882: movq %rbx, %rdi 
.47885: callq .18128 
.47890: movl $1, %esi 
.47895: movq .144008(%rip), %rcx 
.47902: movl $2, %edx 
.47907: leaq .105075(%rip), %rdi 
.47914: callq .19408 
.47919: addq $2, .147960(%rip) 
.47927: popq %rcx 
.47928: popq %rsi 
.47929: movq $0, 8(%rsp) 
.47938: nopw (%rax, %rax) 
.47944: movl $0, (%rbp) 
.47951: movq %r12, %rdi 
.47954: callq .19280 
.47959: movq %rax, %rbx 
.47962: testq %rax, %rax 
.47965: je .48192 
.47971: leaq 0x13(%rax), %r15 
.47975: movl .148208(%rip), %eax 
.47981: cmpl $2, %eax 
.47984: je .48576 
.47990: cmpb $0x2e, 0x13(%rbx) 
.47994: je .48544 
.48000: testl %eax, %eax 
.48002: jne .48576 
.48008: movq .148192(%rip), %r14 
.48015: testq %r14, %r14 
.48018: jne .48045 
.48020: jmp .48576 
.48032: movq 8(%r14), %r14 
.48036: testq %r14, %r14 
.48039: je .48576 
.48045: movq (%r14), %rdi 
.48048: movl $4, %edx 
.48053: movq %r15, %rsi 
.48056: callq .18896 
.48061: testl %eax, %eax 
.48063: jne .48032 
.48065: nopl (%rax) 
.48072: callq .32912 
.48077: jmp .47944 
.48088: cmpb $0, .148152(%rip) 
.48095: je .47929 
.48101: jmp .47751 
.48112: movq %r13, %rsi 
.48115: movl $1, %edi 
.48120: callq .19264 
.48125: shrl $0x1f, %eax 
.48128: testb %al, %al 
.48130: je .47438 
.48136: xorl %edi, %edi 
.48138: movl $5, %edx 
.48143: leaq .105856(%rip), %rsi 
.48150: callq .18592 
.48155: movzbl 0x14(%rsp), %edi 
.48160: movq %r13, %rdx 
.48163: movq %rax, %rsi 
.48166: callq .30704 
.48171: movq %r12, %rdi 
.48174: callq .18976 
.48179: jmp .47601 
.48192: movl (%rbp), %edx 
.48195: testl %edx, %edx 
.48197: je .48244 
.48199: xorl %edi, %edi 
.48201: movl $5, %edx 
.48206: leaq .104578(%rip), %rsi 
.48213: callq .18592 
.48218: movzbl 0x13(%rsp), %edi 
.48223: movq %r13, %rdx 
.48226: movq %rax, %rsi 
.48229: callq .30704 
.48234: cmpl $0x4b, (%rbp) 
.48238: je .48072 
.48244: movq %r12, %rdi 
.48247: callq .18976 
.48252: testl %eax, %eax 
.48254: jne .48768 
.48260: callq .29056 
.48265: cmpb $0, .148214(%rip) 
.48272: jne .48752 
.48278: movl .148280(%rip), %eax 
.48284: testl %eax, %eax 
.48286: je .48301 
.48288: cmpb $0, .148268(%rip) 
.48295: je .48515 
.48301: cmpb $0, .148248(%rip) 
.48308: jne .48888 
.48314: movl $5, %edx 
.48319: leaq .104620(%rip), %rsi 
.48326: xorl %edi, %edi 
.48328: callq .18592 
.48333: movq .144008(%rip), %rsi 
.48340: movq %rax, %rbp 
.48343: movq %rax, %rdi 
.48346: callq .19024 
.48351: movq %rbp, %rdi 
.48354: callq .18624 
.48359: movq .144008(%rip), %rdi 
.48366: addq %rax, .147960(%rip) 
.48373: movq 0x28(%rdi), %rax 
.48377: cmpq 0x30(%rdi), %rax 
.48381: jae .49033 
.48387: leaq 1(%rax), %rdx 
.48391: movq %rdx, 0x28(%rdi) 
.48395: movb $0x20, (%rax) 
.48398: movl .148264(%rip), %edx 
.48404: movq 8(%rsp), %rdi 
.48409: movl $0x200, %ecx 
.48414: leaq 0xb0(%rsp), %rsi 
.48422: movq .148256(%rip), %r8 
.48429: addq $1, .147960(%rip) 
.48437: callq .65440 
.48442: movq .144008(%rip), %rsi 
.48449: movq %rax, %rbp 
.48452: movq %rax, %rdi 
.48455: callq .19024 
.48460: movq %rbp, %rdi 
.48463: callq .18624 
.48468: movq .144008(%rip), %rdi 
.48475: addq %rax, .147960(%rip) 
.48482: movq 0x28(%rdi), %rax 
.48486: cmpq 0x30(%rdi), %rax 
.48490: jae .49048 
.48496: leaq 1(%rax), %rdx 
.48500: movq %rdx, 0x28(%rdi) 
.48504: movb $0xa, (%rax) 
.48507: addq $1, .147960(%rip) 
.48515: cmpq $0, .148400(%rip) 
.48523: je .47601 
.48529: callq .41376 
.48534: jmp .47601 
.48544: testl %eax, %eax 
.48546: je .48072 
.48552: xorl %eax, %eax 
.48554: cmpb $0x2e, 0x14(%rbx) 
.48558: sete %al 
.48561: cmpb $0, 0x14(%rbx, %rax) 
.48566: je .48072 
.48572: nopl (%rax) 
.48576: movq .148200(%rip), %r14 
.48583: testq %r14, %r14 
.48586: jne .48601 
.48588: jmp .48632 
.48592: movq 8(%r14), %r14 
.48596: testq %r14, %r14 
.48599: je .48632 
.48601: movq (%r14), %rdi 
.48604: movl $4, %edx 
.48609: movq %r15, %rsi 
.48612: callq .18896 
.48617: testl %eax, %eax 
.48619: jne .48592 
.48621: jmp .48072 
.48632: movzbl 0x12(%rbx), %eax 
.48636: xorl %esi, %esi 
.48638: subl $1, %eax 
.48641: cmpb $0xd, %al 
.48643: ja .48658 
.48645: movzbl %al, %eax 
.48648: leaq .99776(%rip), %rcx 
.48655: movl (%rcx, %rax, 4), %esi 
.48658: xorl %edx, %edx 
.48660: movq %r13, %rcx 
.48663: movq %r15, %rdi 
.48666: callq .43472 
.48671: addq %rax, 8(%rsp) 
.48676: cmpl $1, .148280(%rip) 
.48683: jne .48072 
.48689: cmpl $-1, .148272(%rip) 
.48696: jne .48072 
.48702: cmpb $0, .148268(%rip) 
.48709: jne .48072 
.48715: cmpb $0, .148214(%rip) 
.48722: jne .48072 
.48728: callq .29056 
.48733: callq .41376 
.48738: callq .28528 
.48743: jmp .48072 
.48752: xorl %esi, %esi 
.48754: movq %r13, %rdi 
.48757: callq .29584 
.48762: jmp .48278 
.48768: xorl %edi, %edi 
.48770: movl $5, %edx 
.48775: leaq .104599(%rip), %rsi 
.48782: callq .18592 
.48787: movzbl 0x14(%rsp), %edi 
.48792: movq %r13, %rdx 
.48795: movq %rax, %rsi 
.48798: callq .30704 
.48803: jmp .48260 
.48816: movl $2, %esi 
.48821: movq %r13, %rdi 
.48824: callq .55552 
.48829: movq %rax, %rbx 
.48832: testq %rax, %rax 
.48835: jne .47835 
.48841: xorl %edi, %edi 
.48843: movl $5, %edx 
.48848: leaq .104473(%rip), %rsi 
.48855: callq .18592 
.48860: movzbl 0x14(%rsp), %edi 
.48865: movq %r13, %rdx 
.48868: movq %rax, %rsi 
.48871: callq .30704 
.48876: jmp .47835 
.48888: movq .144008(%rip), %rcx 
.48895: movl $2, %edx 
.48900: movl $1, %esi 
.48905: leaq .104455(%rip), %rdi 
.48912: callq .19408 
.48917: addq $2, .147960(%rip) 
.48925: jmp .48314 
.48936: movq .144008(%rip), %rcx 
.48943: movl $2, %edx 
.48948: movl $1, %esi 
.48953: leaq .104455(%rip), %rdi 
.48960: callq .19408 
.48965: addq $2, .147960(%rip) 
.48973: jmp .47820 
.48978: xorl %edi, %edi 
.48980: movl $5, %edx 
.48985: leaq .104553(%rip), %rsi 
.48992: callq .18592 
.48997: movzbl 0x14(%rsp), %edi 
.49002: movq %r13, %rdx 
.49005: movq %rax, %rsi 
.49008: callq .30704 
.49013: jmp .47601 
.49018: movl $0xa, %esi 
.49023: callq .18768 
.49028: jmp .47792 
.49033: movl $0x20, %esi 
.49038: callq .18768 
.49043: jmp .48398 
.49048: movl $0xa, %esi 
.49053: callq .18768 
.49058: jmp .48507 
.49063: hlt 
.49068: hlt 
