.60798: nop 
.60800: movaps %xmm0, %xmm1 
.60803: testb %sil, %sil 
.60806: jne .60880 
.60808: testq %rdi, %rdi 
.60811: js .61059 
.60817: pxor %xmm0, %xmm0 
.60821: cvtsi2ssq %rdi, %xmm0 
.60826: divss %xmm1, %xmm0 
.60830: xorl %r8d, %r8d 
.60833: comiss .114568(%rip), %xmm0 
.60840: jae .61055 
.60846: comiss .114572(%rip), %xmm0 
.60853: jb .61089 
.60859: subss .114572(%rip), %xmm0 
.60867: cvttss2si %xmm0, %rdi 
.60872: btcq $0x3f, %rdi 
.60877: nopl (%rax) 
.60880: cmpq $0xa, %rdi 
.60884: movl $0xa, %r8d 
.60890: movabsq $0xaaaaaaaaaaaaaaab, %r9 
.60900: cmovaeq %rdi, %r8 
.60904: orq $1, %r8 
.60908: cmpq $-1, %r8 
.60912: je .61023 
.60914: nopw (%rax, %rax) 
.60920: movq %r8, %rax 
.60923: movq %r8, %rcx 
.60926: mulq %r9 
.60929: movq %rdx, %rax 
.60932: andq $0xfffffffffffffffe, %rdx 
.60936: shrq $1, %rax 
.60939: addq %rdx, %rax 
.60942: subq %rax, %rcx 
.60945: movq %rcx, %rax 
.60948: cmpq $9, %r8 
.60952: jbe .61008 
.60954: testq %rcx, %rcx 
.60957: je .61013 
.60959: movl $0x10, %edi 
.60964: movl $9, %esi 
.60969: movl $3, %ecx 
.60974: jmp .60985 
.60976: addq $8, %rdi 
.60980: testq %rdx, %rdx 
.60983: je .61013 
.60985: addq $2, %rcx 
.60989: movq %r8, %rax 
.60992: xorl %edx, %edx 
.60994: addq %rdi, %rsi 
.60997: divq %rcx 
.61000: movq %rdx, %rax 
.61003: cmpq %rsi, %r8 
.61006: ja .60976 
.61008: testq %rax, %rax 
.61011: jne .61030 
.61013: addq $2, %r8 
.61017: cmpq $-1, %r8 
.61021: jne .60920 
.61023: xorl %r8d, %r8d 
.61026: movq %r8, %rax 
.61029: ret 
.61030: movq %r8, %rax 
.61033: shrq $0x3d, %rax 
.61037: setne %al 
.61040: btq $0x3c, %r8 
.61045: movzbl %al, %eax 
.61048: jb .61023 
.61050: testq %rax, %rax 
.61053: jne .61023 
.61055: movq %r8, %rax 
.61058: ret 
.61059: movq %rdi, %rax 
.61062: andl $1, %edi 
.61065: pxor %xmm0, %xmm0 
.61069: shrq $1, %rax 
.61072: orq %rdi, %rax 
.61075: cvtsi2ssq %rax, %xmm0 
.61080: addss %xmm0, %xmm0 
.61084: jmp .60826 
.61089: cvttss2si %xmm0, %rdi 
.61094: jmp .60880 
