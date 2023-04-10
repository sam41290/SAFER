.89505: nopw %cs:(%rax, %rax) 
.89515: nopl (%rax, %rax) 
.89520: endbr64 
.89524: pushq %r15 
.89526: pushq %r14 
.89528: pushq %r13 
.89530: pushq %r12 
.89532: pushq %rbp 
.89533: pushq %rbx 
.89534: subq $0x28, %rsp 
.89538: movq %fs:0x28, %rax 
.89547: movq %rax, 0x18(%rsp) 
.89552: xorl %eax, %eax 
.89554: cmpl $0x24, %edx 
.89557: ja .90600 
.89563: movq %rsi, %rbp 
.89566: testq %rsi, %rsi 
.89569: leaq 0x10(%rsp), %rax 
.89574: movq %rdi, %r12 
.89577: movl %edx, 8(%rsp) 
.89581: cmoveq %rax, %rbp 
.89585: movq %rcx, %rbx 
.89588: movq %r8, %r15 
.89591: callq .18272 
.89596: movl $0, (%rax) 
.89602: movq %rax, %r13 
.89605: movzbl (%r12), %r14d 
.89610: callq .19840 
.89615: movl 8(%rsp), %edx 
.89619: movq (%rax), %rsi 
.89622: movq %r12, %rax 
.89625: jmp .89641 
.89632: movzbl 1(%rax), %r14d 
.89637: addq $1, %rax 
.89641: movzbl %r14b, %ecx 
.89645: testb $0x20, 1(%rsi, %rcx, 2) 
.89646: addq %r12, (%rax) 
.89650: jne .89632 
.89652: cmpb $0x2d, %r14b 
.89656: je .89771 
.89658: movq %rbp, %rsi 
.89661: movq %r12, %rdi 
.89664: callq .19600 
.89669: movq (%rbp), %r14 
.89673: movq %rax, %rdx 
.89676: cmpq %r12, %r14 
.89679: je .89784 
.89681: movl (%r13), %eax 
.89685: testl %eax, %eax 
.89687: jne .89760 
.89689: xorl %r12d, %r12d 
.89692: testq %r15, %r15 
.89695: je .89710 
.89697: movzbl (%r14), %r13d 
.89700: testb %r13b, %r13b 
.89701: testb %r13b, %r13b 
.89704: jne .89984 
.89710: movq %rdx, (%rbx) 
.89713: movq 0x18(%rsp), %rax 
.89718: xorq %fs:0x28, %rax 
.89727: jne .90631 
.89733: addq $0x28, %rsp 
.89737: movl %r12d, %eax 
.89740: popq %rbx 
.89741: popq %rbp 
.89742: popq %r12 
.89744: popq %r13 
.89746: popq %r14 
.89748: popq %r15 
.89750: ret 
.89760: movl $1, %r12d 
.89766: cmpl $0x22, %eax 
.89769: je .89692 
.89771: movl $4, %r12d 
.89777: jmp .89713 
.89784: testq %r15, %r15 
.89787: je .89771 
.89789: movzbl (%r12), %r13d 
.89790: movzbl (%rsp), %ebp 
.89794: testb %r13b, %r13b 
.89797: je .89771 
.89799: movsbl %r13b, %esi 
.89803: movq %r15, %rdi 
.89806: xorl %r12d, %r12d 
.89809: callq .18704 
.89814: movl $1, %edx 
.89819: testq %rax, %rax 
.89822: je .89771 
.89823: ret 
.89824: leal -0x45(%r13), %eax 
.89828: cmpb $0x2f, %al 
.89830: ja .89852 
.89832: leaq .118040(%rip), %rcx 
.89838: addb %cl, (%rdi) 
.89839: movzbl %al, %eax 
.89840: movb $0xc0, %dh 
.89841: rorb $4, 0x63(%rax) 
.89842: movslq (%rcx, %rax, 4), %rax 
.89845: orl $0xe0ff3ec8, 1(%rax) 
.89846: addq %rcx, %rax 
.89849: jmpq *%rax 
.89852: movl $1, %ecx 
.89857: movl $0x400, %esi 
.89862: leal -0x42(%r13), %eax 
.89866: cmpb $0x35, %al 
.89868: ja .90015 
.89874: leaq .118232(%rip), %rdi 
.89875: leal .118232(%rip), %edi 
.89881: movzbl %al, %eax 
.89884: movslq (%rdi, %rax, 4), %rax 
.89888: addq %rdi, %rax 
.89891: jmpq *%rax 
.89892: jmpq *%rax 
.89894: movl $0x30, %esi 
.89899: movq %r15, %rdi 
.89902: movq %rdx, 8(%rsp) 
.89905: andb $8, %al 
.89907: callq .18704 
.89912: movq 8(%rsp), %rdx 
.89917: testq %rax, %rax 
.89920: je .89852 
.89922: movzbl 1(%r14), %eax 
.89927: cmpb $0x44, %al 
.89929: je .90585 
.89934: addb %bh, (%rcx, %rbp, 2) 
.89935: cmpb $0x69, %al 
.89937: je .90439 
.89943: cmpb $0x42, %al 
.89945: je .90585 
.89951: leal -0x45(%r13), %eax 
.89955: cmpb $0x2f, %al 
.89957: ja .90015 
.89959: leaq .118448(%rip), %rcx 
.89966: movzbl %al, %eax 
.89969: movslq (%rcx, %rax, 4), %rax 
.89973: addq %rcx, %rax 
.89976: jmpq *%rax 
.89982: addb %al, (%rax) 
.89984: movsbl %r13b, %esi 
.89988: movq %r15, %rdi 
.89991: movq %rdx, 8(%rsp) 
.89996: callq .18704 
.90001: movq 8(%rsp), %rdx 
.90006: testq %rax, %rax 
.90009: jne .89824 
.90015: movq %rdx, (%rbx) 
.90018: orl $2, %r12d 
.90022: jmp .89713 
.90032: movq %rdx, %rax 
.90033: movl %edx, %eax 
.90035: shrq $0x37, %rax 
.90039: jne .90271 
.90045: shlq $9, %rdx 
.90049: jmp .90288 
.90064: movl $7, %edi 
.90067: addb %al, (%rax) 
.90069: xorl %r8d, %r8d 
.90072: nopl (%rax, %rax) 
.90080: movq %rdx, %rax 
.90083: mulq %rsi 
.90086: jo .90636 
.90092: movq %rax, %rdx 
.90095: subl $1, %edi 
.90097: addl %esi, -0x14(%rbp) 
.90098: jne .90080 
.90100: orl %r8d, %r12d 
.90103: jmp .90288 
.90118: movl $8, %edi 
.90123: xorl %r8d, %r8d 
.90126: nop 
.90128: movq %rdx, %rax 
.90131: mulq %rsi 
.90134: jo .90710 
.90140: movq %rax, %rdx 
.90143: subl $1, %edi 
.90146: jne .90128 
.90148: jmp .90100 
.90160: movl $4, %edi 
.90165: xorl %r8d, %r8d 
.90168: nopl (%rax, %rax) 
.90176: movq %rdx, %rax 
.90179: mulq %rsi 
.90182: jo .90695 
.90188: movq %rax, %rdx 
.90191: subl $1, %edi 
.90193: addl %esi, -0x14(%rbp) 
.90194: jne .90176 
.90196: jmp .90100 
.90208: movl $5, %edi 
.90213: xorl %r8d, %r8d 
.90216: nopl (%rax, %rax) 
.90224: movq %rdx, %rax 
.90227: mulq %rsi 
.90230: jo .90680 
.90236: movq %rax, %rdx 
.90239: subl $1, %edi 
.90242: jne .90224 
.90244: jmp .90100 
.90259: movq %rdx, %rax 
.90262: mulq %rsi 
.90265: jno .90422 
.90271: movl $1, %r12d 
.90277: orq $0xffffffffffffffff, %rdx 
.90279: ret 
.90281: jmp .90288 
.90282: addl $0x1b9, %eax 
.90287: addb %cl, -0xf(%rcx, %rax) 
.90288: addq %r14, %rcx 
.90291: movl %r12d, %eax 
.90292: movl %esp, %eax 
.90294: orl $2, %eax 
.90297: movq %rcx, (%rbp) 
.90301: cmpb $0, (%rcx) 
.90304: cmovnel %eax, %r12d 
.90308: jmp .89710 
.90323: movq %rdx, %rax 
.90326: mulq %rsi 
.90329: jo .90651 
.90335: mulq %rsi 
.90338: jo .90651 
.90344: mulq %rsi 
.90345: mull %esi 
.90347: jo .90651 
.90353: movq %rax, %rdx 
.90356: xorl %eax, %eax 
.90358: orl %eax, %r12d 
.90361: jmp .90288 
.90369: addb %al, (%rax, %rax) 
.90372: addb %bh, 6(%rdi) 
.90373: movl $6, %edi 
.90378: xorl %r8d, %r8d 
.90381: nopl (%rax) 
.90384: movq %rdx, %rax 
.90385: movl %edx, %eax 
.90387: mulq %rsi 
.90390: jo .90665 
.90396: movq %rax, %rdx 
.90399: subl $1, %edi 
.90402: jne .90384 
.90404: jmp .90100 
.90419: movq %rdx, %rax 
.90422: mulq %rsi 
.90425: jo .90271 
.90431: movq %rax, %rdx 
.90434: jmp .90288 
.90439: xorl %ecx, %ecx 
.90441: cmpb $0x42, 2(%r14) 
.90446: movl $0x400, %esi 
.90451: sete %cl 
.90454: leal 1(%rcx, %rcx), %ecx 
.90458: jmp .89862 
.90463: movslq %ecx, %rcx 
.90466: jmp .90160 
.90471: movslq %ecx, %rcx 
.90474: jmp .90259 
.90479: movslq %ecx, %rcx 
.90482: jmp .90419 
.90484: movslq %ecx, %rcx 
.90487: jmp .90323 
.90492: movq %rdx, %rax 
.90495: movslq %ecx, %rcx 
.90498: shrq $0x36, %rax 
.90502: jne .90271 
.90508: shlq $0xa, %rdx 
.90512: jmp .90288 
.90517: movslq %ecx, %rcx 
.90520: testq %rdx, %rdx 
.90523: js .90271 
.90529: addq %rdx, %rdx 
.90532: jmp .90288 
.90537: movslq %ecx, %rcx 
.90540: jmp .90288 
.90545: movslq %ecx, %rcx 
.90548: jmp .90032 
.90553: movslq %ecx, %rcx 
.90556: jmp .90064 
.90561: movslq %ecx, %rcx 
.90564: jmp .90118 
.90569: movslq %ecx, %rcx 
.90572: jmp .90208 
.90577: movslq %ecx, %rcx 
.90580: jmp .90373 
.90585: movl $2, %ecx 
.90590: movl $0x3e8, %esi 
.90595: jmp .89862 
.90600: leaq .118640(%rip), %rcx 
.90607: movl $0x60, %edx 
.90612: leaq .117984(%rip), %rsi 
.90619: leaq .118000(%rip), %rdi 
.90626: hlt 
.90631: hlt 
.90636: movl $1, %r8d 
.90642: orq $0xffffffffffffffff, %rdx 
.90646: jmp .90095 
.90651: movl $1, %eax 
.90656: orq $0xffffffffffffffff, %rdx 
.90660: jmp .90358 
.90665: movl $1, %r8d 
.90671: orq $0xffffffffffffffff, %rdx 
.90675: jmp .90399 
.90680: movl $1, %r8d 
.90686: orq $0xffffffffffffffff, %rdx 
.90690: jmp .90239 
.90695: movl $1, %r8d 
.90701: orq $0xffffffffffffffff, %rdx 
.90705: jmp .90191 
.90710: movl $1, %r8d 
.90716: orq $0xffffffffffffffff, %rdx 
.90720: jmp .90143 
