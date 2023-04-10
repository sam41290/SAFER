.64505: nopl (%rax) 
.64512: endbr64 
.64516: pushq %r12 
.64518: movl $1, %ecx 
.64523: pushq %rbp 
.64524: pushq %rbx 
.64525: movq %rdi, %rbx 
.64528: subq $0x10, %rsp 
.64532: movq %fs:0x28, %rax 
.64541: movq %rax, 8(%rsp) 
.64546: xorl %eax, %eax 
.64548: movq %rsp, %rdx 
.64551: callq .60416 
.64556: movq %rax, %r12 
.64559: testq %rax, %rax 
.64562: je .64579 
.64564: movq (%rsp), %rax 
.64568: subq $1, 0x20(%rbx) 
.64573: cmpq $0, (%rax) 
.64577: je .64616 
.64579: movq 8(%rsp), %rax 
.64584: xorq %fs:0x28, %rax 
.64593: jne .65015 
.64599: addq $0x10, %rsp 
.64603: movq %r12, %rax 
.64606: popq %rbx 
.64607: popq %rbp 
.64608: popq %r12 
.64610: ret 
.64616: movq 0x18(%rbx), %rax 
.64620: subq $1, %rax 
.64624: movq %rax, 0x18(%rbx) 
.64628: js .64848 
.64634: pxor %xmm0, %xmm0 
.64638: movq 0x28(%rbx), %rdx 
.64642: cvtsi2ssq %rax, %xmm0 
.64647: movq 0x10(%rbx), %rax 
.64651: testq %rax, %rax 
.64654: js .64890 
.64660: pxor %xmm1, %xmm1 
.64664: cvtsi2ssq %rax, %xmm1 
.64669: mulss (%rdx), %xmm1 
.64673: comiss %xmm0, %xmm1 
.64676: jbe .64579 
.64678: leaq 0x28(%rbx), %rdi 
.64682: callq .60672 
.64687: movq 0x10(%rbx), %rax 
.64691: movq 0x28(%rbx), %rdx 
.64695: testq %rax, %rax 
.64698: js .64960 
.64704: pxor %xmm0, %xmm0 
.64708: cvtsi2ssq %rax, %xmm0 
.64713: movq 0x18(%rbx), %rax 
.64717: testq %rax, %rax 
.64720: js .64928 
.64726: pxor %xmm1, %xmm1 
.64730: cvtsi2ssq %rax, %xmm1 
.64735: movss (%rdx), %xmm2 
.64739: mulss %xmm0, %xmm2 
.64743: comiss %xmm1, %xmm2 
.64746: jbe .64579 
.64752: mulss 4(%rdx), %xmm0 
.64757: cmpb $0, 0x10(%rdx) 
.64761: jne .64768 
.64763: mulss 8(%rdx), %xmm0 
.64768: comiss .114572(%rip), %xmm0 
.64775: jae .64992 
.64781: cvttss2si %xmm0, %rsi 
.64786: movq %rbx, %rdi 
.64789: callq .63344 
.64794: testb %al, %al 
.64796: jne .64579 
.64802: movq 0x48(%rbx), %rbp 
.64806: testq %rbp, %rbp 
.64809: je .64833 
.64811: nopl (%rax, %rax) 
.64816: movq %rbp, %rdi 
.64819: movq 8(%rbp), %rbp 
.64823: callq .18128 
.64828: testq %rbp, %rbp 
.64831: jne .64816 
.64833: movq $0, 0x48(%rbx) 
.64841: jmp .64579 
.64848: movq %rax, %rdx 
.64851: andl $1, %eax 
.64854: pxor %xmm0, %xmm0 
.64858: shrq $1, %rdx 
.64861: orq %rax, %rdx 
.64864: movq 0x10(%rbx), %rax 
.64868: cvtsi2ssq %rdx, %xmm0 
.64873: movq 0x28(%rbx), %rdx 
.64877: addss %xmm0, %xmm0 
.64881: testq %rax, %rax 
.64884: jns .64660 
.64890: movq %rax, %rcx 
.64893: andl $1, %eax 
.64896: pxor %xmm1, %xmm1 
.64900: shrq $1, %rcx 
.64903: orq %rax, %rcx 
.64906: cvtsi2ssq %rcx, %xmm1 
.64911: addss %xmm1, %xmm1 
.64915: jmp .64669 
.64928: movq %rax, %rcx 
.64931: andl $1, %eax 
.64934: pxor %xmm1, %xmm1 
.64938: shrq $1, %rcx 
.64941: orq %rax, %rcx 
.64944: cvtsi2ssq %rcx, %xmm1 
.64949: addss %xmm1, %xmm1 
.64953: jmp .64735 
.64960: movq %rax, %rcx 
.64963: andl $1, %eax 
.64966: pxor %xmm0, %xmm0 
.64970: shrq $1, %rcx 
.64973: orq %rax, %rcx 
.64976: cvtsi2ssq %rcx, %xmm0 
.64981: addss %xmm0, %xmm0 
.64985: jmp .64713 
.64992: subss .114572(%rip), %xmm0 
.65000: cvttss2si %xmm0, %rsi 
.65005: btcq $0x3f, %rsi 
.65010: jmp .64786 
.65015: hlt 
