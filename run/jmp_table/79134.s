.78872: leaq .115272(%rip), %rax 
.78879: leaq .118747(%rip), %rdx 
.78886: cmovneq %rdx, %rax 
.78890: addq $8, %rsp 
.78894: popq %rbx 
.78895: popq %rbp 
.78896: ret 
.79134: xorl %edi, %edi 
.79136: movl $5, %edx 
.79141: movl %r10d, 0x10(%rsp) 
.79146: leaq .115289(%rip), %rsi 
.79153: movq %r11, 8(%rsp) 
.79158: callq .18592 
.79163: movq 8(%rsp), %r11 
.79168: movl 0x10(%rsp), %r10d 
.79173: movq %rax, %rdi 
.79176: movq %rax, 0x78(%rsp) 
.79181: leaq .115289(%rip), %rax 
.79188: cmpq %rax, %rdi 
.79191: je .83404 
.79197: xorl %edi, %edi 
.79199: movl $5, %edx 
.79200: addl $0x44000000, %eax 
.79204: movl %r10d, 0x10(%rsp) 
.79205: movl %edx, 0x10(%rsp) 
.79209: leaq .118747(%rip), %rsi 
.79216: movq %r11, 8(%rsp) 
.79221: callq .18592 
.79226: movq 8(%rsp), %r11 
.79231: movl 0x10(%rsp), %r10d 
.79236: movq %rax, %rdi 
.79239: movq %rax, 0x70(%rsp) 
.79244: leaq .118747(%rip), %rax 
.79251: cmpq %rax, %rdi 
.79254: je .83366 
.79260: xorl %r12d, %r12d 
.79263: testl %ebx, %ebx 
.79265: je .82890 
.79271: movq 0x70(%rsp), %rbx 
.79276: movl %r10d, 0x38(%rsp) 
.79281: xorl %r13d, %r13d 
.79284: movq %r11, 0x30(%rsp) 
.79289: movq %rbx, %rdi 
.79292: callq .18624 
.79297: movq %rbx, 0x50(%rsp) 
.79302: movq 0x30(%rsp), %r11 
.79307: movq %rax, 0x20(%rsp) 
.79312: movl 0x38(%rsp), %r10d 
.79316: cmpb %al, %dh 
.79317: movb $1, 8(%rsp) 
.79318: andb $8, %al 
.79321: addl %eax, %esi 
.79322: movb $0, 0x84(%rsp) 
.79323: testb %ah, (%rsp, %rax, 4) 
.79326: addb %al, (%rax) 
.79328: addb %al, (%rax) 
.79330: movq $0, 0x58(%rsp) 
.79339: movb $1, 0x10(%rsp) 
.79344: xorl %ebx, %ebx 
.79346: movl %r13d, %r8d 
.79349: nopl (%rax) 
.79352: cmpq %rbx, %r11 
.79355: setne %r13b 
.79359: cmpq $-1, %r11 
.79363: jne .79378 
.79365: movq 0x18(%rsp), %rax 
.79370: cmpb $0, (%rax, %rbx) 
.79374: setne %r13b 
.79378: testb %r13b, %r13b 
.79381: je .81560 
.79383: jge .79393 
.79385: addb %al, (%rax) 
.79387: cmpl $2, %r10d 
.79391: movq 0x18(%rsp), %rdi 
.79393: jl .79431 
.79395: sbbb %cl, (%rdi) 
.79396: setne %al 
.79397: xchgl %ebp, %eax 
.79398: shlb $0x44, (%rdx) 
.79399: andb 0x10(%rsp), %al 
.79401: andb $0x10, %al 
.79403: leaq (%rdi, %rbx), %rbp 
.79407: movl %eax, %r9d 
.79410: je .81136 
.79416: movq 0x20(%rsp), %rax 
.79421: testq %rax, %rax 
.79424: je .81472 
.79430: leaq (%rbx, %rax), %rdx 
.79431: leal (%rbx, %rax), %edx 
.79434: cmpq $-1, %r11 
.79438: jne .79496 
.79440: cmpq $1, %rax 
.79444: jbe .79496 
.79446: movl %r10d, 0x48(%rsp) 
.79451: movb %r8b, 0x40(%rsp) 
.79456: movb %r9b, 0x38(%rsp) 
.79461: movq %rdx, 0x30(%rsp) 
.79466: callq .18624 
.79471: movl 0x48(%rsp), %r10d 
.79476: movzbl 0x40(%rsp), %r8d 
.79482: movzbl 0x38(%rsp), %r9d 
.79488: movq 0x30(%rsp), %rdx 
.79492: xorb %cl, -0x77(%rcx) 
.79493: movq %rax, %r11 
.79495: ret 
.79496: cmpq %r11, %rdx 
.79499: ja .81472 
.79505: movq 0x20(%rsp), %rdx 
.79510: movq 0x50(%rsp), %rsi 
.79515: movq %rbp, %rdi 
.79518: movl %r10d, 0x48(%rsp) 
.79523: movq %r11, 0x40(%rsp) 
.79528: movb %r8b, 0x38(%rsp) 
.79533: movb %r9b, 0x30(%rsp) 
.79538: callq .18992 
.79543: movzbl 0x30(%rsp), %r9d 
.79549: movzbl 0x38(%rsp), %r8d 
.79555: testl %eax, %eax 
.79557: movq 0x40(%rsp), %r11 
.79562: movl 0x48(%rsp), %r10d 
.79567: jne .81472 
.79573: cmpb $0, 0x63(%rsp) 
.79578: jne .80606 
.79584: movzbl (%rbp), %ebp 
.79588: cmpb $0x7e, %bpl 
.79592: ja .79891 
.79598: leaq .115404(%rip), %rcx 
.79605: movzbl %bpl, %edx 
.79609: movslq (%rcx, %rdx, 4), %rax 
.79613: addq %rcx, %rax 
.79616: jmpq *%rax 
.79624: movl %r9d, %eax 
.79627: nopl (%rax, %rax) 
.79632: movl %r9d, %r13d 
.79635: movl %eax, %r9d 
.79638: xorl %eax, %eax 
.79640: nopl (%rax, %rax) 
.79648: movq 0x28(%rsp), %rsi 
.79653: testq %rsi, %rsi 
.79656: je .79678 
.79658: movl %ebp, %edx 
.79660: movl %ebp, %ecx 
.79662: shrb $5, %dl 
.79665: movzbl %dl, %edx 
.79668: movl (%rsi, %rdx, 4), %edx 
.79671: shrl %cl, %edx 
.79673: andl $1, %edx 
.79676: jne .79687 
.79678: testb %r9b, %r9b 
.79681: je .79873 
.79687: cmpl $2, %r10d 
.79691: sete %dl 
.79692: xchgl %esp, %eax 
.79693: ret 
.79694: cmpb $0, 0x63(%rsp) 
.79699: movl %edx, %eax 
.79701: jne .80960 
.79707: movl %r8d, %eax 
.79710: xorl $1, %eax 
.79713: andb %dl, %al 
.79715: je .79766 
.79717: cmpq %r12, %r14 
.79720: jbe .79727 
.79722: movb $0x27, (%r15, %r12) 
.79727: leaq 1(%r12), %rdx 
.79732: cmpq %rdx, %r14 
.79735: jbe .79743 
.79737: movb $0x24, 1(%r15, %r12) 
.79743: leaq 2(%r12), %rdx 
.79748: cmpq %rdx, %r14 
.79751: jbe .79759 
.79753: movb $0x27, 2(%r15, %r12) 
.79759: addq $3, %r12 
.79763: movl %eax, %r8d 
.79766: cmpq %r12, %r14 
.79767: cmpl %esp, %esi 
.79769: jbe .79776 
.79771: movb $0x5c, (%r15, %r12) 
.79776: addq $1, %r12 
.79780: addq $1, %rbx 
.79784: cmpq %r14, %r12 
.79787: jae .79793 
.79789: movb %bpl, (%r15, %r12) 
.79793: movzbl 8(%rsp), %edi 
.79798: addq $1, %r12 
.79802: movl $0, %eax 
.79807: testb %r13b, %r13b 
.79810: cmovel %eax, %edi 
.79813: movb %dil, 8(%rsp) 
.79818: jmp .79352 
.79824: xorl %r9d, %r9d 
.79827: xorl %eax, %eax 
.79829: xorl %r13d, %r13d 
.79832: movzbl 0x10(%rsp), %edx 
.79837: xorl $1, %edx 
.79840: orb %dl, %al 
.79842: je .79648 
.79848: xorl %eax, %eax 
.79850: cmpb $0, 0x63(%rsp) 
.79855: jne .79648 
.79861: nopl (%rax) 
.79864: testb %r9b, %r9b 
.79867: jne .79687 
.79873: xorl $1, %eax 
.79876: addq $1, %rbx 
.79880: andl %r8d, %eax 
.79883: jmp .81248 
.79888: xorl %r9d, %r9d 
.79891: cmpq $1, 0x68(%rsp) 
.79897: jne .81784 
.79903: movl %r10d, 0x48(%rsp) 
.79907: movq %r11, 0x40(%rsp) 
.79908: movq %r11, 0x40(%rsp) 
.79913: movb %r8b, 0x38(%rsp) 
.79918: movb %r9b, 0x30(%rsp) 
.79923: callq .19840 
.79928: movzbl 0x30(%rsp), %r9d 
.79934: movzbl 0x38(%rsp), %r8d 
.79940: movl $1, %edi 
.79945: movq %rax, %r13 
.79948: movzbl %bpl, %eax 
.79952: movq 0x40(%rsp), %r11 
.79953: movl 0x40(%rsp), %ebx 
.79957: movl 0x48(%rsp), %r10d 
.79960: andb $0x48, %al 
.79962: movq (%r13), %rdx 
.79966: movzwl (%rdx, %rax, 2), %eax 
.79967: movb $4, %bh 
.79969: andw $0x4000, %ax 
.79970: andw $0x4000, %ax 
.79974: setne %r13b 
.79978: sete %dl 
.79981: andb 0x10(%rsp), %dl 
.79985: testb %dl, %dl 
.79987: jne .82737 
.79993: nopl (%rax) 
.80000: cmpl $2, %r10d 
.80004: sete %al 
.80007: jmp .79832 
.80047: leaq .118747(%rip), %rax 
.80054: xorl %r12d, %r12d 
.80057: movl $2, %r10d 
.80063: movq $1, 0x20(%rsp) 
.80072: movq %rax, 0x50(%rsp) 
.80077: jmp .79344 
.80085: testl %ecx, 0xc(%rcx) 
.80088: addb %al, (%rax) 
.80090: testq %r14, %r14 
.80093: je .82789 
.80099: movb $0x22, (%r15) 
.80103: xorl %r13d, %r13d 
.80106: movb $1, 8(%rsp) 
.80111: movb $0, 0x84(%rsp) 
.80119: movq $0, 0x58(%rsp) 
.80128: leaq .115272(%rip), %rax 
.80135: movb $0, 0x63(%rsp) 
.80140: movl $1, %r12d 
.80146: movb $1, 0x10(%rsp) 
.80151: movq $1, 0x20(%rsp) 
.80160: movq %rax, 0x50(%rsp) 
.80165: jmp .79344 
.80183: testq %r14, %r14 
.80186: jne .83553 
.80192: movq $0, 0x58(%rsp) 
.80201: xorl %r13d, %r13d 
.80204: movb $1, 8(%rsp) 
.80209: movb $0, 0x84(%rsp) 
.80217: leaq .118747(%rip), %rax 
.80224: movb $0, 0x63(%rsp) 
.80229: movl $1, %r12d 
.80235: movl $2, %r10d 
.80241: movq $1, 0x20(%rsp) 
.80250: movq %rax, 0x50(%rsp) 
.80255: jmp .79344 
.80260: leaq .115272(%rip), %rax 
.80267: xorl %r13d, %r13d 
.80270: xorl %r12d, %r12d 
.80273: movb $1, 8(%rsp) 
.80275: andb $8, %al 
.80277: addl %eax, %esi 
.80278: movb $0, 0x84(%rsp) 
.80279: testb %ah, (%rsp, %rax, 4) 
.80282: addb %al, (%rax) 
.80284: addb %al, (%rax) 
.80286: movl $5, %r10d 
.80292: movq $0, 0x58(%rsp) 
.80301: movb $1, 0x63(%rsp) 
.80306: movb $1, 0x10(%rsp) 
.80308: andb $0x10, %al 
.80310: addl %ecx, -0x39(%rax) 
.80311: movq $1, 0x20(%rsp) 
.80313: andb $0x20, %al 
.80316: addl %eax, (%rax) 
.80318: addb %al, (%rax) 
.80320: movq %rax, 0x50(%rsp) 
.80325: jmp .79344 
.80415: addb %al, (%rax) 
.80417: addb %al, (%rax) 
.80419: movb $0, 0x63(%rsp) 
.80424: movb $0, 0x10(%rsp) 
.80429: movq $0, 0x20(%rsp) 
.80438: movq $0, 0x50(%rsp) 
.80447: jmp .79344 
.80461: testb %ah, (%rsp, %rax, 4) 
.80464: addb %al, (%rax) 
.80466: addb %al, (%rax) 
.80468: movq $0, 0x58(%rsp) 
.80475: addb %al, (%rax) 
.80477: movb $1, 0x63(%rsp) 
.80482: movb $1, 0x10(%rsp) 
.80487: jmp .80047 
.80503: adcb %al, (%rax) 
.80505: jmp .80183 
.80512: xorl %r9d, %r9d 
.80515: cmpq $1, %r11 
.80519: setne %dl 
.80522: cmpq $-1, %r11 
.80526: jne .80540 
.80527: orb $0x48, %al 
.80528: movq 0x18(%rsp), %rax 
.80529: movl 0x18(%rsp), %eax 
.80533: cmpb $0, 1(%rax) 
.80537: setne %dl 
.80540: cmpl $2, %r10d 
.80544: sete %al 
.80547: testb %dl, %dl 
.80549: jne .79829 
.80555: testq %rbx, %rbx 
.80558: jne .79829 
.80564: cmpb $0, 0x63(%rsp) 
.80569: je .79832 
.80575: testb %al, %al 
.80577: je .79832 
.80583: movl $2, %r10d 
.80589: nopl (%rax) 
.80592: cmpb $0, 0x10(%rsp) 
.80593: jl .80631 
.80595: adcb %al, (%rax) 
.80597: movl $4, %eax 
.80602: cmovnel %eax, %r10d 
.80606: subq $8, %rsp 
.80610: movl %r10d, %r8d 
.80611: movl %edx, %eax 
.80613: movq %r11, %rcx 
.80616: pushq 0x78(%rsp) 
.80620: movq %r14, %rsi 
.80623: movq %r15, %rdi 
.80626: pushq 0x88(%rsp) 
.80631: addb %al, (%rax) 
.80633: pushq $0 
.80635: movl 0x84(%rsp), %r9d 
.80643: movq 0x38(%rsp), %rdx 
.80648: andl $0xfffffffd, %r9d 
.80652: callq .78960 
.80657: addq $0x20, %rsp 
.80661: movq %rax, %r12 
.80664: movq 0xa8(%rsp), %rax 
.80668: testb $0, %al 
.80670: addb %al, (%rax) 
.80672: xorq %fs:0x28, %rax 
.80681: jne .83548 
.80683: subl $0x4800000b, %eax 
.80687: addq $0xb8, %rsp 
.80688: addl $0xb8, %esp 
.80694: movq %r12, %rax 
.80695: movl %esp, %eax 
.80697: popq %rbx 
.80698: popq %rbp 
.80699: popq %r12 
.80701: popq %r13 
.80703: popq %r14 
.80705: popq %r15 
.80707: ret 
.80708: xorl %r9d, %r9d 
.80711: cmpl $2, %r10d 
.80715: je .81752 
.80721: cmpl $5, %r10d 
.80725: jne .80768 
.80727: testb $4, 0x64(%rsp) 
.80732: je .80768 
.80734: leaq 2(%rbx), %rax 
.80738: cmpq %r11, %rax 
.80741: jae .80768 
.80743: movq 0x18(%rsp), %rdi 
.80748: cmpb $0x3f, 1(%rdi, %rbx) 
.80753: je .83005 
.80759: nopw (%rax, %rax) 
.80768: xorl %eax, %eax 
.80770: xorl %r13d, %r13d 
.80773: movl $0x3f, %ebp 
.80778: jmp .79832 
.80783: xorl %r9d, %r9d 
.80786: cmpl $2, %r10d 
.80790: je .81680 
.80796: movb %r13b, 0x84(%rsp) 
.80804: xorl %eax, %eax 
.80806: movl $0x27, %ebp 
.80811: jmp .79832 
.80816: xorl %r9d, %r9d 
.80818: leave 
.80819: nopl (%rax, %rax) 
.80824: movzbl 0x63(%rsp), %ecx 
.80829: testb %cl, 0x10(%rsp) 
.80833: je .80847 
.80835: cmpq $0, 0x20(%rsp) 
.80841: jne .81224 
.80847: movl $0x5c, %ebp 
.80852: movl $0x5c, %edx 
.80857: nopl (%rax) 
.80864: cmpb $0, 0x10(%rsp) 
.80869: jne .83575 
.80875: xorl %r13d, %r13d 
.80878: xorl %eax, %eax 
.80880: cmpb $0, 0x63(%rsp) 
.80885: jne .79648 
.80891: jmp .79864 
.80896: movl $0x61, %ebp 
.80901: cmpl $2, %r10d 
.80905: sete %al 
.80908: cmpb $0, 0x63(%rsp) 
.80913: jne .80960 
.80915: xorl %r13d, %r13d 
.80916: xorl %ebp, %ebp 
.80918: jmp .79766 
.80923: movl $0x72, %ebp 
.80928: xorl %r13d, %r13d 
.80931: cmpl $2, %r10d 
.80935: sete %dl 
.80938: cmpb $0, 0x63(%rsp) 
.80943: movl %edx, %eax 
.80945: je .79707 
.80951: nopw (%rax, %rax) 
.80960: andb %al, 0x10(%rsp) 
.80964: jmp .80592 
.80969: movl $0x66, %ebp 
.80974: jmp .80901 
.80976: movl $0x6e, %ebp 
.80981: jmp .80928 
.80983: movl $0x62, %ebp 
.80988: jmp .80901 
.80990: cmpb $0, 0x63(%rsp) 
.80995: jne .83442 
.81001: xorl %r9d, %r9d 
.81004: cmpl $2, %r10d 
.81008: movl %r8d, %eax 
.81011: sete %dl 
.81014: xorl $1, %eax 
.81017: andb %dl, %al 
.81019: je .82576 
.81025: cmpq %r12, %r14 
.81028: jbe .81035 
.81030: movb $0x27, (%r15, %r12) 
.81035: leaq 1(%r12), %rcx 
.81040: cmpq %rcx, %r14 
.81043: jbe .81051 
.81045: movb $0x24, 1(%r15, %r12) 
.81051: leaq 2(%r12), %rcx 
.81056: cmpq %rcx, %r14 
.81059: jbe .81067 
.81061: movb $0x27, 2(%r15, %r12) 
.81067: leaq 3(%r12), %rcx 
.81072: cmpq %rcx, %r14 
.81075: ja .82587 
.81081: addq $4, %r12 
.81085: movl %eax, %r8d 
.81088: xorl %r13d, %r13d 
.81091: movl $0x30, %ebp 
.81096: jmp .79678 
.81101: xorl %r9d, %r9d 
.81104: movl $9, %ebp 
.81109: movl $0x74, %edx 
.81114: jmp .80864 
.81119: movl $0x76, %ebp 
.81124: jmp .80928 
.81136: movzbl (%rbp), %ebp 
.81140: cmpb $0x7e, %bpl 
.81144: ja .79891 
.81150: leaq .115912(%rip), %rcx 
.81157: movzbl %bpl, %edx 
.81161: movslq (%rcx, %rdx, 4), %rax 
.81165: addq %rcx, %rax 
.81168: jmpq *%rax 
.81176: cmpl $2, %r10d 
.81180: sete %al 
.81183: xorl %r13d, %r13d 
.81186: jmp .80564 
.81191: cmpl $2, %r10d 
.81195: sete %al 
.81198: jmp .80555 
.81203: cmpl $2, %r10d 
.81207: jne .80824 
.81213: cmpb $0, 0x63(%rsp) 
.81218: jne .80592 
.81224: addq $1, %rbx 
.81228: movl %r8d, %eax 
.81231: xorl %r13d, %r13d 
.81234: movl $0x5c, %ebp 
.81239: nopw (%rax, %rax) 
.81248: testb %al, %al 
.81250: je .79784 
.81256: cmpq %r12, %r14 
.81259: jbe .81266 
.81261: movb $0x27, (%r15, %r12) 
.81266: leaq 1(%r12), %rax 
.81271: cmpq %rax, %r14 
.81274: jbe .81282 
.81276: movb $0x27, 1(%r15, %r12) 
.81282: addq $2, %r12 
.81286: xorl %r8d, %r8d 
.81289: jmp .79784 
.81294: cmpl $2, %r10d 
.81298: movl $0x20, %ebp 
.81303: sete %al 
.81306: jmp .80564 
.81311: movl $0xc, %ebp 
.81316: movl $0x66, %edx 
.81321: jmp .80864 
.81326: movl $9, %ebp 
.81331: movl $0x74, %edx 
.81336: cmpl $2, %r10d 
.81340: sete %al 
.81343: andb 0x63(%rsp), %al 
.81347: movl %eax, %r9d 
.81350: je .80864 
.81356: jmp .80583 
.81361: movl $8, %ebp 
.81366: movl $0x62, %edx 
.81371: jmp .80864 
.81376: cmpb $0, 0x10(%rsp) 
.81381: jne .80990 
.81387: xorl %r9d, %r9d 
.81390: xorl %ebp, %ebp 
.81392: testb $1, 0x64(%rsp) 
.81397: je .80875 
.81403: addq $1, %rbx 
.81407: jmp .79352 
.81412: movl $0xd, %ebp 
.81417: movl $0x72, %edx 
.81422: jmp .81336 
.81424: movl $0xb, %ebp 
.81429: movl $0x76, %edx 
.81434: jmp .80864 
.81439: movl $0xa, %ebp 
.81444: movl $0x6e, %edx 
.81449: jmp .81336 
.81451: movl $7, %ebp 
.81456: movl $0x61, %edx 
.81461: jmp .80864 
.81472: movzbl (%rbp), %ebp 
.81476: cmpb $0x7e, %bpl 
.81480: ja .79888 
.81486: leaq .116420(%rip), %rcx 
.81493: movzbl %bpl, %edx 
.81497: movslq (%rcx, %rdx, 4), %rax 
.81501: addq %rcx, %rax 
.81504: jmpq *%rax 
.81512: xorl %eax, %eax 
.81514: jmp .79632 
.81519: xorl %eax, %eax 
.81521: testq %rbx, %rbx 
.81524: jne .82560 
.81530: movl %r9d, %r13d 
.81533: movl %eax, %r9d 
.81536: xorl %eax, %eax 
.81538: jmp .79832 
.81543: xorl %eax, %eax 
.81545: movl $0x20, %ebp 
.81550: jmp .79632 
.81560: cmpl $2, %r10d 
.81564: movl %r8d, %r13d 
.81567: sete %dl 
.81570: testq %r12, %r12 
.81573: jne .81585 
.81575: testb %dl, 0x63(%rsp) 
.81579: jne .80583 
.81585: movzbl 0x63(%rsp), %eax 
.81590: xorl $1, %eax 
.81593: andb %al, %dl 
.81595: je .83299 
.81601: cmpb $0, 0x84(%rsp) 
.81609: je .83301 
.81615: cmpb $0, 8(%rsp) 
.81620: jne .83469 
.81626: testq %r14, %r14 
.81629: sete %al 
.81632: cmpq $0, 0x58(%rsp) 
.81638: setne %dl 
.81641: andb %dl, %al 
.81643: je .83456 
.81649: movq 0x58(%rsp), %rdx 
.81654: movq 0x58(%rsp), %r14 
.81659: movb $0x27, (%r15) 
.81663: movb %al, 0x84(%rsp) 
.81670: movq %rdx, 0x58(%rsp) 
.81675: jmp .80217 
.81680: cmpb $0, 0x63(%rsp) 
.81685: jne .80592 
.81691: testq %r14, %r14 
.81694: je .82678 
.81700: xorl %edx, %edx 
.81702: cmpq $0, 0x58(%rsp) 
.81708: jne .82678 
.81714: movq %r14, 0x58(%rsp) 
.81719: addq $3, %r12 
.81723: xorl %eax, %eax 
.81725: xorl %r8d, %r8d 
.81728: movb %r13b, 0x84(%rsp) 
.81736: movq %rdx, %r14 
.81739: movl $0x27, %ebp 
.81744: jmp .79678 
.81752: cmpb $0, 0x63(%rsp) 
.81757: jne .80592 
.81763: xorl %r13d, %r13d 
.81766: xorl %eax, %eax 
.81768: movl $0x3f, %ebp 
.81773: jmp .79678 
.81784: leaq 0xa0(%rsp), %rax 
.81792: movq $0, 0xa0(%rsp) 
.81804: movq %rax, 0x38(%rsp) 
.81809: cmpq $-1, %r11 
.81813: jne .81860 
.81815: movq 0x18(%rsp), %rdi 
.81820: movl %r10d, 0x48(%rsp) 
.81825: movb %r8b, 0x40(%rsp) 
.81830: movb %r9b, 0x30(%rsp) 
.81835: callq .18624 
.81840: movl 0x48(%rsp), %r10d 
.81845: movzbl 0x40(%rsp), %r8d 
.81851: movzbl 0x30(%rsp), %r9d 
.81857: movq %rax, %r11 
.81860: leaq 0x9c(%rsp), %rax 
.81868: movb %r13b, 0x30(%rsp) 
.81873: xorl %edi, %edi 
.81875: movq %rax, 0x48(%rsp) 
.81880: movb %r8b, 0x85(%rsp) 
.81888: movb %r9b, 0x87(%rsp) 
.81896: movl %r10d, 0x80(%rsp) 
.81904: movq %r12, 0x88(%rsp) 
.81912: movq 0x38(%rsp), %r12 
.81917: movq %rbx, 0x40(%rsp) 
.81922: movq %r11, %rbx 
.81925: movb %bpl, 0x86(%rsp) 
.81933: movq %rdi, %rbp 
.81936: movq 0x40(%rsp), %rax 
.81941: movq 0x48(%rsp), %rdi 
.81946: movq %rbx, %rdx 
.81949: movq %r12, %rcx 
.81952: leaq (%rax, %rbp), %r13 
.81956: movq 0x18(%rsp), %rax 
.81961: subq %r13, %rdx 
.81964: leaq (%rax, %r13), %rsi 
.81968: callq .92368 
.81973: movq %rax, %rdx 
.81976: testq %rax, %rax 
.81979: je .82083 
.81981: cmpq $-1, %rax 
.81985: je .82939 
.81991: cmpq $-2, %rax 
.81995: je .83127 
.82001: cmpl $2, 0x80(%rsp) 
.82009: jne .82022 
.82011: cmpb $0, 0x63(%rsp) 
.82016: jne .82464 
.82022: movl 0x9c(%rsp), %edi 
.82025: pushfq 
.82026: addb %al, (%rax) 
.82028: addb %cl, -0x77(%rax) 
.82029: movq %rdx, 0x38(%rsp) 
.82031: pushq %rsp 
.82032: andb $0x38, %al 
.82034: callq .19792 
.82039: movzbl 0x30(%rsp), %edi 
.82044: movq 0x38(%rsp), %rdx 
.82049: testl %eax, %eax 
.82051: movl $0, %eax 
.82056: cmovel %eax, %edi 
.82059: addq %rdx, %rbp 
.82062: movb %dil, 0x30(%rsp) 
.82067: movq %r12, %rdi 
.82070: callq .19776 
.82075: testl %eax, %eax 
.82077: je .81936 
.82083: movzbl 0x30(%rsp), %r13d 
.82089: movq %rbp, %rdi 
.82092: movq %rbx, %r11 
.82095: movzbl 0x85(%rsp), %r8d 
.82104: movzbl 0x86(%rsp), %ebp 
.82112: movq 0x88(%rsp), %r12 
.82120: movl %r13d, %edx 
.82123: movq 0x40(%rsp), %rbx 
.82128: movzbl 0x87(%rsp), %r9d 
.82137: movl 0x80(%rsp), %r10d 
.82145: xorl $1, %edx 
.82148: andb 0x10(%rsp), %dl 
.82152: cmpq $1, %rdi 
.82156: jbe .79985 
.82162: movq %rdi, %rcx 
.82165: movb %r13b, 0x30(%rsp) 
.82170: movq 0x18(%rsp), %rdi 
.82175: xorl %esi, %esi 
.82177: movzbl 0x63(%rsp), %r13d 
.82183: addq %rbx, %rcx 
.82186: jmp .82369 
.82192: cmpl $2, %r10d 
.82196: sete %al 
.82199: testb %r13b, %r13b 
.82202: jne .82761 
.82208: movl %r8d, %esi 
.82211: xorl $1, %esi 
.82214: andb %sil, %al 
.82217: je .82268 
.82219: cmpq %r12, %r14 
.82222: jbe .82229 
.82224: movb $0x27, (%r15, %r12) 
.82229: leaq 1(%r12), %rsi 
.82234: cmpq %rsi, %r14 
.82237: jbe .82245 
.82239: movb $0x24, 1(%r15, %r12) 
.82245: leaq 2(%r12), %rsi 
.82250: cmpq %rsi, %r14 
.82253: jbe .82261 
.82255: movb $0x27, 2(%r15, %r12) 
.82261: addq $3, %r12 
.82265: movl %eax, %r8d 
.82268: cmpq %r12, %r14 
.82271: jbe .82278 
.82273: movb $0x5c, (%r15, %r12) 
.82278: leaq 1(%r12), %rax 
.82283: cmpq %rax, %r14 
.82286: jbe .82301 
.82288: movl %ebp, %eax 
.82290: shrb $6, %al 
.82293: addl $0x30, %eax 
.82296: movb %al, 1(%r15, %r12) 
.82301: leaq 2(%r12), %rax 
.82306: cmpq %rax, %r14 
.82309: jbe .82327 
.82311: movl %ebp, %eax 
.82313: shrb $3, %al 
.82316: andl $7, %eax 
.82319: addl $0x30, %eax 
.82322: movb %al, 2(%r15, %r12) 
.82327: andl $7, %ebp 
.82330: addq $1, %rbx 
.82334: addq $3, %r12 
.82338: addl $0x30, %ebp 
.82341: cmpq %rcx, %rbx 
.82344: jae .82770 
.82350: movl %edx, %esi 
.82352: cmpq %r12, %r14 
.82355: jbe .82361 
.82357: movb %bpl, (%r15, %r12) 
.82361: movzbl (%rdi, %rbx), %ebp 
.82365: addq $1, %r12 
.82369: testb %dl, %dl 
.82371: jne .82192 
.82377: movl %esi, %eax 
.82379: xorl $1, %eax 
.82382: andl %r8d, %eax 
.82385: testb %r9b, %r9b 
.82388: je .82404 
.82390: cmpq %r12, %r14 
.82393: jbe .82400 
.82395: movb $0x5c, (%r15, %r12) 
.82400: addq $1, %r12 
.82404: addq $1, %rbx 
.82408: cmpq %rcx, %rbx 
.82411: jae .82750 
.82417: testb %al, %al 
.82419: je .82781 
.82425: cmpq %r12, %r14 
.82428: jbe .82435 
.82430: movb $0x27, (%r15, %r12) 
.82435: leaq 1(%r12), %rax 
.82440: cmpq %rax, %r14 
.82443: jbe .82451 
.82445: movb $0x27, 1(%r15, %r12) 
.82451: addq $2, %r12 
.82455: xorl %r9d, %r9d 
.82458: xorl %r8d, %r8d 
.82461: jmp .82352 
.82464: cmpq $1, %rax 
.82468: je .82022 
.82474: movq 0x18(%rsp), %rax 
.82479: leaq 1(%rax, %r13), %rsi 
.82484: addq %rdx, %rax 
.82487: leaq (%rax, %r13), %r8 
.82491: jmp .82506 
.82493: addq $1, %rsi 
.82497: cmpq %rsi, %r8 
.82500: je .82022 
.82506: movzbl (%rsi), %eax 
.82509: leal -0x5b(%rax), %ecx 
.82512: cmpb $0x21, %cl 
.82515: ja .82493 
.82517: movl $1, %eax 
.82522: shlq %cl, %rax 
.82525: movabsq $0x20000002b, %rcx 
.82533: addb %al, (%rax) 
.82535: testq %rcx, %rax 
.82538: je .82493 
.82540: movq %rbx, %r11 
.82543: movl $2, %r10d 
.82549: jmp .80592 
.82560: movl %eax, %r9d 
.82563: xorl %r13d, %r13d 
.82566: xorl %eax, %eax 
.82568: jmp .79648 
.82576: movq %r12, %rcx 
.82579: cmpq %r12, %r14 
.82582: jbe .82595 
.82584: movl %r8d, %eax 
.82587: movb $0x5c, (%r15, %rcx) 
.82592: movl %eax, %r8d 
.82595: leaq 1(%rcx), %r12 
.82599: cmpl $2, %r10d 
.82603: je .82819 
.82609: leaq 1(%rbx), %rax 
.82613: movl $0x30, %ebp 
.82618: cmpq %r11, %rax 
.82621: jae .82648 
.82623: movq 0x18(%rsp), %rax 
.82628: movzbl 1(%rax, %rbx), %eax 
.82633: movb %al, 0x30(%rsp) 
.82637: subl $0x30, %eax 
.82640: cmpb $9, %al 
.82642: jbe .82835 
.82648: movzbl 0x10(%rsp), %eax 
.82653: xorl $1, %eax 
.82656: orb %dl, %al 
.82658: movl %r13d, %eax 
.82661: movl $0, %r13d 
.82667: je .79648 
.82673: jmp .79678 
.82678: cmpq %r12, %r14 
.82681: jbe .82688 
.82683: movb $0x27, (%r15, %r12) 
.82688: leaq 1(%r12), %rax 
.82693: cmpq %rax, %r14 
.82696: jbe .82704 
.82698: movb $0x5c, 1(%r15, %r12) 
.82704: leaq 2(%r12), %rax 
.82709: cmpq %rax, %r14 
.82712: jbe .83535 
.82718: movq %r14, %rdx 
.82721: movb $0x27, 2(%r15, %r12) 
.82727: movq 0x58(%rsp), %r14 
.82732: jmp .81714 
.82737: movzbl 0x10(%rsp), %edx 
.82742: xorl %r13d, %r13d 
.82745: jmp .82162 
.82750: movzbl 0x30(%rsp), %r13d 
.82756: jmp .81248 
.82761: movb %al, 0x10(%rsp) 
.82765: jmp .80592 
.82770: movzbl 0x30(%rsp), %r13d 
.82776: jmp .79784 
.82781: xorl %r9d, %r9d 
.82784: jmp .82352 
.82789: movq $0, 0x58(%rsp) 
.82798: xorl %r13d, %r13d 
.82801: movb $1, 8(%rsp) 
.82806: movb $0, 0x84(%rsp) 
.82814: jmp .80128 
.82819: movl %r13d, %eax 
.82822: movl $0x30, %ebp 
.82827: xorl %r13d, %r13d 
.82830: jmp .79678 
.82835: cmpq %r12, %r14 
.82838: jbe .82845 
.82840: movb $0x30, (%r15, %r12) 
.82845: leaq 2(%rcx), %rax 
.82849: cmpq %rax, %r14 
.82852: jbe .82860 
.82854: movb $0x30, 2(%r15, %rcx) 
.82860: leaq 3(%rcx), %r12 
.82864: movl $0x30, %ebp 
.82869: jmp .82648 
.82874: movl %r9d, %eax 
.82877: jmp .81521 
.82882: movl %r9d, %eax 
.82885: jmp .81545 
.82890: movq 0x78(%rsp), %rdx 
.82895: movzbl (%rdx), %eax 
.82898: testb %al, %al 
.82900: je .79271 
.82906: nopw (%rax, %rax) 
.82912: cmpq %r12, %r14 
.82915: jbe .82921 
.82917: movb %al, (%r15, %r12) 
.82921: addq $1, %r12 
.82925: movzbl (%rdx, %r12), %eax 
.82930: testb %al, %al 
.82932: jne .82912 
.82934: jmp .79271 
.82939: movq %rbp, %rdi 
.82942: movq %rbx, %r11 
.82945: movzbl 0x10(%rsp), %edx 
.82950: movq 0x40(%rsp), %rbx 
.82955: movzbl 0x85(%rsp), %r8d 
.82964: movzbl 0x86(%rsp), %ebp 
.82972: xorl %r13d, %r13d 
.82975: movq 0x88(%rsp), %r12 
.82983: movl 0x80(%rsp), %r10d 
.82991: movzbl 0x87(%rsp), %r9d 
.83000: jmp .82152 
.83005: movzbl (%rdi, %rax), %ebp 
.83009: leal -0x21(%rbp), %edx 
.83012: cmpb $0x1d, %dl 
.83015: ja .80768 
.83021: leaq .116928(%rip), %rdi 
.83028: movzbl %dl, %edx 
.83031: movslq (%rdi, %rdx, 4), %rdx 
.83035: addq %rdi, %rdx 
.83038: jmpq *%rdx 
.83041: cmpb $0, 0x63(%rsp) 
.83046: jne .80606 
.83052: cmpq %r12, %r14 
.83055: jbe .83062 
.83057: movb $0x3f, (%r15, %r12) 
.83062: leaq 1(%r12), %rdx 
.83067: cmpq %rdx, %r14 
.83070: jbe .83078 
.83072: movb $0x22, 1(%r15, %r12) 
.83078: leaq 2(%r12), %rdx 
.83083: cmpq %rdx, %r14 
.83086: jbe .83094 
.83088: movb $0x22, 2(%r15, %r12) 
.83094: leaq 3(%r12), %rdx 
.83099: cmpq %rdx, %r14 
.83102: jbe .83110 
.83104: movb $0x3f, 3(%r15, %r12) 
.83110: addq $4, %r12 
.83114: xorl %edx, %edx 
.83116: xorl %r13d, %r13d 
.83119: movq %rax, %rbx 
.83122: jmp .82648 
.83127: movq %rbp, %rdi 
.83130: movq %rbx, %r11 
.83133: movq 0x18(%rsp), %rcx 
.83138: movq 0x40(%rsp), %rbx 
.83143: movzbl 0x85(%rsp), %r8d 
.83152: movq %r13, %rax 
.83155: movq %rdi, %rdx 
.83158: movzbl 0x86(%rsp), %ebp 
.83166: movq 0x88(%rsp), %r12 
.83174: movl 0x80(%rsp), %r10d 
.83182: movzbl 0x87(%rsp), %r9d 
.83191: cmpq %r11, %r13 
.83194: jb .83213 
.83196: jmp .83222 
.83200: addq $1, %rdx 
.83204: leaq (%rbx, %rdx), %rax 
.83208: cmpq %rax, %r11 
.83211: jbe .83219 
.83213: cmpb $0, (%rcx, %rax) 
.83217: jne .83200 
.83219: movq %rdx, %rdi 
.83222: movzbl 0x10(%rsp), %edx 
.83227: xorl %r13d, %r13d 
.83230: jmp .82152 
.83235: leaq .115272(%rip), %rax 
.83242: xorl %r13d, %r13d 
.83245: xorl %r12d, %r12d 
.83248: movb $1, 8(%rsp) 
.83253: movb $0, 0x84(%rsp) 
.83261: movq $0, 0x58(%rsp) 
.83270: movb $1, 0x63(%rsp) 
.83275: movb $1, 0x10(%rsp) 
.83280: movq $1, 0x20(%rsp) 
.83289: movq %rax, 0x50(%rsp) 
.83294: jmp .79344 
.83299: movl %eax, %edx 
.83301: movq 0x50(%rsp), %rax 
.83306: testq %rax, %rax 
.83309: je .83347 
.83311: testb %dl, %dl 
.83313: je .83347 
.83315: movzbl (%rax), %edx 
.83318: testb %dl, %dl 
.83320: je .83347 
.83322: subq %r12, %rax 
.83325: cmpq %r12, %r14 
.83328: jbe .83334 
.83330: movb %dl, (%r15, %r12) 
.83334: addq $1, %r12 
.83338: movzbl (%rax, %r12), %edx 
.83343: testb %dl, %dl 
.83345: jne .83325 
.83347: cmpq %r12, %r14 
.83350: jbe .80664 
.83356: movb $0, (%r15, %r12) 
.83361: jmp .80664 
.83366: movl %r10d, %esi 
.83369: movq %r11, 0x10(%rsp) 
.83374: movl %r10d, 8(%rsp) 
.83379: callq .78736 
.83384: movq 0x10(%rsp), %r11 
.83389: movl 8(%rsp), %r10d 
.83394: movq %rax, 0x70(%rsp) 
.83399: jmp .79260 
.83404: movl %r10d, %esi 
.83407: movq %r11, 0x10(%rsp) 
.83412: movl %r10d, 8(%rsp) 
.83417: callq .78736 
.83422: movq 0x10(%rsp), %r11 
.83427: movl 8(%rsp), %r10d 
.83432: movq %rax, 0x78(%rsp) 
.83437: jmp .79197 
.83442: cmpl $2, %r10d 
.83446: sete 0x10(%rsp) 
.83451: jmp .80592 
.83456: movzbl 0x84(%rsp), %edx 
.83464: jmp .83301 
.83469: subq $8, %rsp 
.83473: movl $5, %r8d 
.83479: movq %r11, %rcx 
.83482: movq %r15, %rdi 
.83485: pushq 0x78(%rsp) 
.83489: pushq 0x88(%rsp) 
.83496: pushq 0x40(%rsp) 
.83500: movl 0x84(%rsp), %r9d 
.83508: movq 0x38(%rsp), %rdx 
.83513: movq 0x78(%rsp), %rsi 
.83518: callq .78960 
.83523: addq $0x20, %rsp 
.83527: movq %rax, %r12 
.83530: jmp .80664 
.83535: movq %r14, %rdx 
.83538: movq 0x58(%rsp), %r14 
.83543: jmp .81714 
.83548: hlt 
.83553: movq %r14, 0x58(%rsp) 
.83558: xorl %edx, %edx 
.83560: xorl %r13d, %r13d 
.83563: xorl %eax, %eax 
.83565: movb $1, 8(%rsp) 
.83570: jmp .81654 
.83575: movl %edx, %ebp 
.83577: jmp .80928 
.83582: leaq .118747(%rip), %rax 
.83589: xorl %r13d, %r13d 
.83592: xorl %r12d, %r12d 
.83595: movb $1, 8(%rsp) 
.83600: movb $0, 0x84(%rsp) 
.83608: movq $0, 0x58(%rsp) 
.83617: movb $1, 0x63(%rsp) 
.83622: movb $0, 0x10(%rsp) 
.83627: movq $1, 0x20(%rsp) 
.83636: movq %rax, 0x50(%rsp) 
.83641: jmp .79344 
