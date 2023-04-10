.31848: nopl (%rax, %rax) 
.31856: endbr64 
.31860: movl 0xa8(%rdi), %eax 
.31866: movl 0xa8(%rsi), %ecx 
.31872: cmpl $3, %eax 
.31875: sete %dl 
.31878: cmpl $9, %eax 
.31881: sete %al 
.31884: orl %eax, %edx 
.31886: cmpl $9, %ecx 
.31889: sete %al 
.31892: cmpl $3, %ecx 
.31895: sete %cl 
.31898: orb %cl, %al 
.31900: jne .31920 
.31902: testb %dl, %dl 
.31904: jne .31936 
.31906: movl $1, %r8d 
.31912: testb %al, %al 
.31914: je .31924 
.31916: movl %r8d, %eax 
.31919: ret 
.31920: testb %dl, %dl 
.31922: je .31906 
.31924: movq (%rsi), %rsi 
.31927: movq (%rdi), %rdi 
.31930: jmp .59104 
.31936: movl $0xffffffff, %r8d 
.31942: jmp .31916 
.59104: endbr64 
.59108: pushq %r14 
.59110: pushq %r13 
.59112: pushq %r12 
.59114: pushq %rbp 
.59115: movq %rsi, %rbp 
.59118: pushq %rbx 
.59119: movq %rdi, %rbx 
.59122: subq $0x20, %rsp 
.59126: movq %fs:0x28, %rax 
.59135: movq %rax, 0x18(%rsp) 
.59140: xorl %eax, %eax 
.59142: callq .19072 
.59147: movl %eax, %r12d 
.59150: testl %eax, %eax 
.59152: je .59206 
.59154: movzbl (%rbx), %eax 
.59157: testb %al, %al 
.59159: je .59724 
.59165: movzbl (%rbp), %edx 
.59169: testb %dl, %dl 
.59171: je .59200 
.59173: cmpb $0x2e, (%rbx) 
.59176: jne .59188 
.59178: cmpb $0, 1(%rbx) 
.59182: je .59724 
.59188: cmpb $0x2e, (%rbp) 
.59192: jne .59248 
.59194: cmpb $0, 1(%rbp) 
.59198: jne .59248 
.59200: movl $1, %r12d 
.59206: movq 0x18(%rsp), %rax 
.59211: xorq %fs:0x28, %rax 
.59220: jne .60097 
.59226: addq $0x20, %rsp 
.59230: movl %r12d, %eax 
.59233: popq %rbx 
.59234: popq %rbp 
.59235: popq %r12 
.59237: popq %r13 
.59239: popq %r14 
.59241: ret 
.59248: cmpb $0x2e, (%rbx) 
.59251: jne .59276 
.59253: movzbl 1(%rbx), %ecx 
.59257: movl $0x2e, %esi 
.59262: cmpl %ecx, %esi 
.59264: jne .59276 
.59266: cmpb $0, 2(%rbx) 
.59270: je .59724 
.59276: cmpb $0x2e, (%rbp) 
.59280: je .59680 
.59286: cmpb $0x2e, %al 
.59288: sete %cl 
.59291: cmpb $0x2e, %dl 
.59294: je .59304 
.59296: testb %cl, %cl 
.59298: jne .59724 
.59304: cmpb $0x2e, %dl 
.59307: sete %dl 
.59310: cmpb $0x2e, %al 
.59312: je .59968 
.59318: testb %dl, %dl 
.59320: jne .59200 
.59322: leaq 8(%rsp), %rdi 
.59327: movq %rbx, 8(%rsp) 
.59332: movq %rbp, 0x10(%rsp) 
.59337: callq .58928 
.59342: leaq 0x10(%rsp), %rdi 
.59347: movq %rax, %r14 
.59350: callq .58928 
.59355: movq %rax, %r13 
.59358: testq %r14, %r14 
.59361: je .60016 
.59367: subq %rbx, %r14 
.59370: testq %rax, %rax 
.59373: je .60110 
.59379: subq %rbp, %r13 
.59382: cmpq %r13, %r14 
.59385: je .60048 
.59391: xorl %ecx, %ecx 
.59393: xorl %edx, %edx 
.59395: cmpq %rdx, %r14 
.59398: ja .59409 
.59400: cmpq %rcx, %r13 
.59403: jbe .59206 
.59409: movq %rcx, %r8 
.59412: subq %rdx, %r8 
.59415: cmpq %rdx, %r14 
.59418: jbe .59535 
.59420: movzbl (%rbx, %rdx), %esi 
.59424: movsbl %sil, %eax 
.59428: subl $0x30, %eax 
.59431: cmpl $9, %eax 
.59434: jbe .59535 
.59436: movzbl %sil, %eax 
.59440: leal -0x30(%rax), %edi 
.59443: cmpl $9, %edi 
.59446: ja .59590 
.59452: cmpq %rcx, %r13 
.59455: je .59522 
.59457: movzbl (%rbp, %rcx), %edi 
.59462: movl %edi, %esi 
.59464: movzbl %dil, %edi 
.59468: xorl %r9d, %r9d 
.59471: leal -0x30(%rdi), %eax 
.59474: cmpl $9, %eax 
.59477: jbe .59522 
.59479: movl %edi, %eax 
.59481: cmpb $0x5a, %sil 
.59485: jg .59944 
.59491: cmpb $0x40, %sil 
.59495: jg .59513 
.59497: cmpb $0x7e, %sil 
.59501: je .60089 
.59507: leal 0x100(%rdi), %eax 
.59513: cmpl %r9d, %eax 
.59516: jne .59997 
.59522: addq $1, %rdx 
.59526: addq $1, %rcx 
.59530: cmpq %rdx, %r14 
.59533: ja .59420 
.59535: movzbl (%rbp, %rcx), %edi 
.59540: movsbl %dil, %esi 
.59544: cmpq %rcx, %r13 
.59547: jbe .59748 
.59553: movsbl %dil, %eax 
.59557: subl $0x30, %eax 
.59560: cmpl $9, %eax 
.59563: jbe .59748 
.59569: cmpq %rdx, %r14 
.59572: je .59464 
.59574: movzbl (%rbx, %rdx), %eax 
.59578: leal -0x30(%rax), %r9d 
.59582: movl %eax, %esi 
.59584: cmpl $9, %r9d 
.59588: jbe .59462 
.59590: movl %eax, %r9d 
.59593: cmpb $0x5a, %sil 
.59597: jg .59904 
.59603: cmpb $0x40, %sil 
.59607: jg .59917 
.59613: cmpb $0x7e, %sil 
.59617: je .60080 
.59623: leal 0x100(%rax), %r9d 
.59630: leaq (%rdx, %r8), %rax 
.59634: cmpq %rax, %r13 
.59637: je .60000 
.59643: movzbl (%rbp, %rcx), %esi 
.59648: xorl %eax, %eax 
.59650: movzbl %sil, %edi 
.59654: leal -0x30(%rdi), %r10d 
.59658: cmpl $9, %r10d 
.59662: jbe .59513 
.59668: jmp .59479 
.59680: movzbl 1(%rbp), %ecx 
.59684: movl $0x2e, %esi 
.59689: cmpl %ecx, %esi 
.59691: jne .59286 
.59697: cmpb $0, 2(%rbp) 
.59701: je .59200 
.59707: jmp .59286 
.59712: subl $0x30, %esi 
.59715: cmpl $9, %esi 
.59718: ja .59395 
.59724: movl $0xffffffff, %r12d 
.59730: jmp .59206 
.59744: addq $1, %rdx 
.59748: movsbl (%rbx, %rdx), %eax 
.59752: cmpb $0x30, %al 
.59754: je .59744 
.59756: cmpb $0x30, %dil 
.59760: jne .59783 
.59762: nopw (%rax, %rax) 
.59768: addq $1, %rcx 
.59772: movsbl (%rbp, %rcx), %esi 
.59777: cmpb $0x30, %sil 
.59781: je .59768 
.59783: leal -0x30(%rax), %edi 
.59786: cmpl $9, %edi 
.59789: ja .59712 
.59791: movq %rcx, %r9 
.59794: movq %rdx, %rdi 
.59797: xorl %r8d, %r8d 
.59800: subq %rdx, %r9 
.59803: leaq (%rbp, %r9), %r10 
.59808: leal -0x30(%rsi), %r9d 
.59812: cmpl $9, %r9d 
.59816: ja .59200 
.59822: subl %esi, %eax 
.59824: testl %r8d, %r8d 
.59827: cmovel %eax, %r8d 
.59831: addq $1, %rdi 
.59835: movsbl (%rbx, %rdi), %eax 
.59839: movq %rdi, %r9 
.59842: movsbl (%r10, %rdi), %esi 
.59847: subq %rdx, %r9 
.59850: leal -0x30(%rax), %r11d 
.59854: addq %rcx, %r9 
.59857: cmpl $9, %r11d 
.59861: jbe .59808 
.59863: movsbl %sil, %edx 
.59867: subl $0x30, %edx 
.59870: cmpl $9, %edx 
.59873: jbe .59724 
.59879: testl %r8d, %r8d 
.59882: jne .60102 
.59888: movq %rdi, %rdx 
.59891: movq %r9, %rcx 
.59894: jmp .59395 
.59904: leal -0x61(%rsi), %edi 
.59907: cmpb $0x19, %dil 
.59911: ja .59613 
.59917: leaq (%rdx, %r8), %rsi 
.59921: xorl %eax, %eax 
.59923: cmpq %rsi, %r13 
.59926: jne .59643 
.59932: jmp .59513 
.59944: leal -0x61(%rsi), %r10d 
.59948: cmpb $0x19, %r10b 
.59952: jbe .59513 
.59958: jmp .59497 
.59968: testb %dl, %dl 
.59970: je .59322 
.59976: testb %cl, %cl 
.59978: je .59322 
.59984: addq $1, %rbx 
.59988: addq $1, %rbp 
.59992: jmp .59322 
.59997: subl %eax, %r9d 
.60000: testl %r9d, %r9d 
.60003: cmovnel %r9d, %r12d 
.60007: jmp .59206 
.60016: movq 8(%rsp), %r14 
.60021: subq %rbx, %r14 
.60024: testq %rax, %rax 
.60027: jne .59379 
.60033: movq 0x10(%rsp), %r13 
.60038: subq %rbp, %r13 
.60041: jmp .59391 
.60048: movq %r14, %rdx 
.60051: movq %rbp, %rsi 
.60054: movq %rbx, %rdi 
.60057: callq .18288 
.60062: testl %eax, %eax 
.60064: jne .59391 
.60070: movq 8(%rsp), %r14 
.60075: subq %rbx, %r14 
.60078: jmp .60033 
.60080: orl $0xffffffff, %r9d 
.60084: jmp .59630 
.60089: orl $0xffffffff, %eax 
.60092: jmp .59513 
.60097: hlt 
.60102: movl %r8d, %r12d 
.60105: jmp .59206 
.60110: movq 0x10(%rsp), %r13 
.60115: jmp .59379 
