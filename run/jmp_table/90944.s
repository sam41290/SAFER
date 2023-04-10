.90944: endbr64 
.90948: pushq %r15 
.90950: pushq %r14 
.90952: pushq %r13 
.90954: pushq %r12 
.90956: pushq %rbp 
.90957: pushq %rbx 
.90958: subq $0x28, %rsp 
.90962: movq %fs:0x28, %rax 
.90971: movq %rax, 0x18(%rsp) 
.90976: xorl %eax, %eax 
.90978: cmpl $0x24, %edx 
.90981: ja .92024 
.90987: movq %rsi, %rbp 
.90990: testq %rsi, %rsi 
.90993: leaq 0x10(%rsp), %rax 
.90998: movq %rdi, %r12 
.91001: movl %edx, 8(%rsp) 
.91005: cmoveq %rax, %rbp 
.91009: movq %rcx, %rbx 
.91012: movq %r8, %r15 
.91015: callq .18272 
.91020: movl $0, (%rax) 
.91026: movq %rax, %r13 
.91029: movzbl (%r12), %r14d 
.91034: callq .19840 
.91039: movl 8(%rsp), %edx 
.91043: movq (%rax), %rsi 
.91046: movq %r12, %rax 
.91049: jmp .91065 
.91051: nopl (%rax, %rax) 
.91056: movzbl 1(%rax), %r14d 
.91061: addq $1, %rax 
.91065: movzbl %r14b, %ecx 
.91069: testb $0x20, 1(%rsi, %rcx, 2) 
.91070: addq %r12, (%rax) 
.91074: jne .91056 
.91076: cmpb $0x2d, %r14b 
.91080: je .91195 
.91082: xorl %ecx, %ecx 
.91084: movq %rbp, %rsi 
.91087: movq %r12, %rdi 
.91090: callq .18880 
.91095: movq (%rbp), %r14 
.91099: movq %rax, %rdx 
.91102: cmpq %r12, %r14 
.91105: je .91208 
.91107: movl (%r13), %eax 
.91111: testl %eax, %eax 
.91113: jne .91184 
.91115: xorl %r12d, %r12d 
.91118: testq %r15, %r15 
.91121: je .91136 
.91123: movzbl (%r14), %r13d 
.91124: movzbl (%rsi), %ebp 
.91127: testb %r13b, %r13b 
.91130: jne .91408 
.91136: movq %rdx, (%rbx) 
.91139: movq 0x18(%rsp), %rax 
.91144: xorq %fs:0x28, %rax 
.91153: jne .92055 
.91159: addq $0x28, %rsp 
.91163: movl %r12d, %eax 
.91166: popq %rbx 
.91167: popq %rbp 
.91168: popq %r12 
.91170: popq %r13 
.91172: popq %r14 
.91174: popq %r15 
.91176: ret 
.91177: nopl (%rax) 
.91184: movl $1, %r12d 
.91190: cmpl $0x22, %eax 
.91193: je .91118 
.91195: movl $4, %r12d 
.91201: jmp .91139 
.91203: nopl (%rax, %rax) 
.91208: testq %r15, %r15 
.91211: je .91195 
.91213: movzbl (%r12), %r13d 
.91214: movzbl (%rsp), %ebp 
.91218: testb %r13b, %r13b 
.91221: je .91195 
.91223: movsbl %r13b, %esi 
.91227: movq %r15, %rdi 
.91230: xorl %r12d, %r12d 
.91233: callq .18704 
.91238: movl $1, %edx 
.91243: testq %rax, %rax 
.91246: je .91195 
.91247: ret 
.91248: leal -0x45(%r13), %eax 
.91252: cmpb $0x2f, %al 
.91254: ja .91276 
.91256: leaq .118752(%rip), %rcx 
.91262: addb %cl, (%rdi) 
.91263: movzbl %al, %eax 
.91264: movb $0xc0, %dh 
.91265: rorb $4, 0x63(%rax) 
.91266: movslq (%rcx, %rax, 4), %rax 
.91269: orl $0xe0ff3ec8, 1(%rax) 
.91270: addq %rcx, %rax 
.91273: jmpq *%rax 
.91276: movl $1, %ecx 
.91281: movl $0x400, %esi 
.91286: leal -0x42(%r13), %eax 
.91290: cmpb $0x35, %al 
.91292: ja .91439 
.91298: leaq .118944(%rip), %rdi 
.91299: leal .118944(%rip), %edi 
.91305: movzbl %al, %eax 
.91308: movslq (%rdi, %rax, 4), %rax 
.91312: addq %rdi, %rax 
.91315: jmpq *%rax 
.91316: jmpq *%rax 
.91318: movl $0x30, %esi 
.91323: movq %r15, %rdi 
.91326: movq %rdx, 8(%rsp) 
.91329: andb $8, %al 
.91331: callq .18704 
.91336: movq 8(%rsp), %rdx 
.91341: testq %rax, %rax 
.91344: je .91276 
.91346: movzbl 1(%r14), %eax 
.91351: cmpb $0x44, %al 
.91353: je .92009 
.91358: addb %bh, (%rcx, %rbp, 2) 
.91359: cmpb $0x69, %al 
.91361: je .91863 
.91367: cmpb $0x42, %al 
.91369: je .92009 
.91375: leal -0x45(%r13), %eax 
.91379: cmpb $0x2f, %al 
.91381: ja .91439 
.91383: leaq .119160(%rip), %rcx 
.91390: movzbl %al, %eax 
.91393: movslq (%rcx, %rax, 4), %rax 
.91397: addq %rcx, %rax 
.91400: jmpq *%rax 
.91403: nopl (%rax, %rax) 
.91406: addb %al, (%rax) 
.91408: movsbl %r13b, %esi 
.91412: movq %r15, %rdi 
.91415: movq %rdx, 8(%rsp) 
.91420: callq .18704 
.91425: movq 8(%rsp), %rdx 
.91430: testq %rax, %rax 
.91433: jne .91248 
.91439: movq %rdx, (%rbx) 
.91442: orl $2, %r12d 
.91446: jmp .91139 
.91451: movl $1, %ecx 
.91456: movq %rdx, %rax 
.91457: movl %edx, %eax 
.91459: shrq $0x37, %rax 
.91463: jne .91695 
.91469: shlq $9, %rdx 
.91473: jmp .91712 
.91478: movl $1, %ecx 
.91483: movl $0x400, %esi 
.91488: movl $7, %edi 
.91491: addb %al, (%rax) 
.91493: xorl %r8d, %r8d 
.91496: nopl (%rax, %rax) 
.91504: movq %rdx, %rax 
.91507: mulq %rsi 
.91510: jo .92060 
.91516: movq %rax, %rdx 
.91519: subl $1, %edi 
.91521: addl %esi, -0x14(%rbp) 
.91522: jne .91504 
.91524: orl %r8d, %r12d 
.91527: jmp .91712 
.91532: movl $1, %ecx 
.91537: movl $0x400, %esi 
.91542: movl $8, %edi 
.91547: xorl %r8d, %r8d 
.91550: nop 
.91552: movq %rdx, %rax 
.91555: mulq %rsi 
.91558: jo .92134 
.91564: movq %rax, %rdx 
.91567: subl $1, %edi 
.91570: jne .91552 
.91572: jmp .91524 
.91574: movl $1, %ecx 
.91579: movl $0x400, %esi 
.91584: movl $4, %edi 
.91589: xorl %r8d, %r8d 
.91592: nopl (%rax, %rax) 
.91600: movq %rdx, %rax 
.91603: mulq %rsi 
.91606: jo .92119 
.91612: movq %rax, %rdx 
.91615: subl $1, %edi 
.91617: addl %esi, -0x14(%rbp) 
.91618: jne .91600 
.91620: jmp .91524 
.91622: movl $1, %ecx 
.91627: movl $0x400, %esi 
.91632: movl $5, %edi 
.91637: xorl %r8d, %r8d 
.91640: nopl (%rax, %rax) 
.91648: movq %rdx, %rax 
.91651: mulq %rsi 
.91654: jo .92104 
.91660: movq %rax, %rdx 
.91663: subl $1, %edi 
.91666: jne .91648 
.91668: jmp .91524 
.91673: movl $1, %ecx 
.91678: movl $0x400, %esi 
.91683: movq %rdx, %rax 
.91686: mulq %rsi 
.91689: jno .91846 
.91695: movl $1, %r12d 
.91701: orq $0xffffffffffffffff, %rdx 
.91703: ret 
.91705: jmp .91712 
.91706: addl $0x1b9, %eax 
.91707: movl $1, %ecx 
.91711: addb %cl, -0xf(%rcx, %rax) 
.91712: addq %r14, %rcx 
.91715: movl %r12d, %eax 
.91716: movl %esp, %eax 
.91718: orl $2, %eax 
.91721: movq %rcx, (%rbp) 
.91725: cmpb $0, (%rcx) 
.91728: cmovnel %eax, %r12d 
.91732: jmp .91136 
.91737: movl $1, %ecx 
.91742: movl $0x400, %esi 
.91747: movq %rdx, %rax 
.91750: mulq %rsi 
.91753: jo .92075 
.91759: mulq %rsi 
.91762: jo .92075 
.91768: mulq %rsi 
.91769: mull %esi 
.91771: jo .92075 
.91777: movq %rax, %rdx 
.91780: xorl %eax, %eax 
.91782: orl %eax, %r12d 
.91785: jmp .91712 
.91787: movl $1, %ecx 
.91792: movl $0x400, %esi 
.91793: addb %al, (%rax, %rax) 
.91796: addb %bh, 6(%rdi) 
.91797: movl $6, %edi 
.91802: xorl %r8d, %r8d 
.91805: nopl (%rax) 
.91808: movq %rdx, %rax 
.91809: movl %edx, %eax 
.91811: mulq %rsi 
.91814: jo .92089 
.91820: movq %rax, %rdx 
.91823: subl $1, %edi 
.91826: jne .91808 
.91828: jmp .91524 
.91833: movl $1, %ecx 
.91838: movl $0x400, %esi 
.91843: movq %rdx, %rax 
.91846: mulq %rsi 
.91849: jo .91695 
.91855: movq %rax, %rdx 
.91858: jmp .91712 
.91863: xorl %ecx, %ecx 
.91865: cmpb $0x42, 2(%r14) 
.91870: movl $0x400, %esi 
.91875: sete %cl 
.91878: leal 1(%rcx, %rcx), %ecx 
.91882: jmp .91286 
.91887: movslq %ecx, %rcx 
.91890: jmp .91584 
.91895: movslq %ecx, %rcx 
.91898: jmp .91683 
.91903: movslq %ecx, %rcx 
.91906: jmp .91843 
.91908: movslq %ecx, %rcx 
.91911: jmp .91747 
.91916: movq %rdx, %rax 
.91919: movslq %ecx, %rcx 
.91922: shrq $0x36, %rax 
.91926: jne .91695 
.91932: shlq $0xa, %rdx 
.91936: jmp .91712 
.91941: movslq %ecx, %rcx 
.91944: testq %rdx, %rdx 
.91947: js .91695 
.91953: addq %rdx, %rdx 
.91956: jmp .91712 
.91961: movslq %ecx, %rcx 
.91964: jmp .91712 
.91969: movslq %ecx, %rcx 
.91972: jmp .91456 
.91977: movslq %ecx, %rcx 
.91980: jmp .91488 
.91985: movslq %ecx, %rcx 
.91988: jmp .91542 
.91993: movslq %ecx, %rcx 
.91996: jmp .91632 
.92001: movslq %ecx, %rcx 
.92004: jmp .91797 
.92009: movl $2, %ecx 
.92014: movl $0x3e8, %esi 
.92019: jmp .91286 
.92024: leaq .119352(%rip), %rcx 
.92031: movl $0x60, %edx 
.92036: leaq .117984(%rip), %rsi 
.92043: leaq .118000(%rip), %rdi 
.92050: hlt 
.92055: hlt 
.92060: movl $1, %r8d 
.92066: orq $0xffffffffffffffff, %rdx 
.92070: jmp .91519 
.92075: movl $1, %eax 
.92080: orq $0xffffffffffffffff, %rdx 
.92084: jmp .91782 
.92089: movl $1, %r8d 
.92095: orq $0xffffffffffffffff, %rdx 
.92099: jmp .91823 
.92104: movl $1, %r8d 
.92110: orq $0xffffffffffffffff, %rdx 
.92114: jmp .91663 
.92119: movl $1, %r8d 
.92125: orq $0xffffffffffffffff, %rdx 
.92129: jmp .91615 
.92134: movl $1, %r8d 
.92140: orq $0xffffffffffffffff, %rdx 
.92144: jmp .91567 
