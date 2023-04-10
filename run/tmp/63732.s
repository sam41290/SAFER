.19897: hlt 
.63732: nopw %cs:(%rax, %rax) 
.63743: nop 
.63744: endbr64 
.63748: pushq %r13 
.63750: pushq %r12 
.63752: pushq %rbp 
.63753: pushq %rbx 
.63754: subq $0x18, %rsp 
.63758: movq %fs:0x28, %rax 
.63767: movq %rax, 8(%rsp) 
.63772: xorl %eax, %eax 
.63774: testq %rsi, %rsi 
.63777: je .19897 
.63783: movq %rsp, %r12 
.63786: movq %rdx, %r13 
.63789: xorl %ecx, %ecx 
.63791: movq %rdi, %rbx 
.63794: movq %r12, %rdx 
.63797: movq %rsi, %rbp 
.63800: callq .60416 
.63805: testq %rax, %rax 
.63808: je .63856 
.63810: xorl %r8d, %r8d 
.63813: testq %r13, %r13 
.63816: je .63822 
.63818: movq %rax, (%r13) 
.63822: movq 8(%rsp), %rax 
.63827: xorq %fs:0x28, %rax 
.63836: jne .64404 
.63842: addq $0x18, %rsp 
.63846: movl %r8d, %eax 
.63849: popq %rbx 
.63850: popq %rbp 
.63851: popq %r12 
.63853: popq %r13 
.63855: ret 
.63856: movq 0x18(%rbx), %rax 
.63860: testq %rax, %rax 
.63863: js .63984 
.63865: pxor %xmm1, %xmm1 
.63869: movq 0x28(%rbx), %rdx 
.63873: cvtsi2ssq %rax, %xmm1 
.63878: movq 0x10(%rbx), %rax 
.63882: testq %rax, %rax 
.63885: js .64026 
.63891: pxor %xmm0, %xmm0 
.63895: cvtsi2ssq %rax, %xmm0 
.63900: mulss 8(%rdx), %xmm0 
.63905: comiss %xmm0, %xmm1 
.63908: ja .64065 
.63914: movq (%rsp), %r12 
.63918: cmpq $0, (%r12) 
.63923: je .64184 
.63929: movq 0x48(%rbx), %rax 
.63933: testq %rax, %rax 
.63936: je .64216 
.63942: movq 8(%rax), %rdx 
.63946: movq %rdx, 0x48(%rbx) 
.63950: movq 8(%r12), %rdx 
.63955: movq %rbp, (%rax) 
.63958: movl $1, %r8d 
.63964: movq %rdx, 8(%rax) 
.63968: movq %rax, 8(%r12) 
.63973: addq $1, 0x20(%rbx) 
.63978: jmp .63822 
.63984: movq %rax, %rdx 
.63987: andl $1, %eax 
.63990: pxor %xmm1, %xmm1 
.63994: shrq $1, %rdx 
.63997: orq %rax, %rdx 
.64000: movq 0x10(%rbx), %rax 
.64004: cvtsi2ssq %rdx, %xmm1 
.64009: movq 0x28(%rbx), %rdx 
.64013: addss %xmm1, %xmm1 
.64017: testq %rax, %rax 
.64020: jns .63891 
.64026: movq %rax, %rcx 
.64029: andl $1, %eax 
.64032: pxor %xmm0, %xmm0 
.64036: shrq $1, %rcx 
.64039: orq %rax, %rcx 
.64042: cvtsi2ssq %rcx, %xmm0 
.64047: addss %xmm0, %xmm0 
.64051: mulss 8(%rdx), %xmm0 
.64056: comiss %xmm0, %xmm1 
.64059: jbe .63914 
.64065: leaq 0x28(%rbx), %rdi 
.64069: callq .60672 
.64074: movq 0x28(%rbx), %rdx 
.64078: movq 0x10(%rbx), %rax 
.64082: movss 8(%rdx), %xmm2 
.64087: testq %rax, %rax 
.64090: js .64272 
.64096: pxor %xmm0, %xmm0 
.64100: cvtsi2ssq %rax, %xmm0 
.64105: movq 0x18(%rbx), %rax 
.64109: testq %rax, %rax 
.64112: js .64240 
.64114: pxor %xmm1, %xmm1 
.64118: cvtsi2ssq %rax, %xmm1 
.64123: movaps %xmm2, %xmm3 
.64126: mulss %xmm0, %xmm3 
.64130: comiss %xmm3, %xmm1 
.64133: jbe .63914 
.64139: mulss 0xc(%rdx), %xmm0 
.64144: cmpb $0, 0x10(%rdx) 
.64148: je .64304 
.64154: comiss .114568(%rip), %xmm0 
.64161: jb .64320 
.64167: movl $0xffffffff, %r8d 
.64173: jmp .63822 
.64184: movq %rbp, (%r12) 
.64188: movl $1, %r8d 
.64194: addq $1, 0x20(%rbx) 
.64199: addq $1, 0x18(%rbx) 
.64204: jmp .63822 
.64216: movl $0x10, %edi 
.64221: callq .18144 
.64226: testq %rax, %rax 
.64229: je .64167 
.64231: jmp .63950 
.64240: movq %rax, %rcx 
.64243: andl $1, %eax 
.64246: pxor %xmm1, %xmm1 
.64250: shrq $1, %rcx 
.64253: orq %rax, %rcx 
.64256: cvtsi2ssq %rcx, %xmm1 
.64261: addss %xmm1, %xmm1 
.64265: jmp .64123 
.64272: movq %rax, %rcx 
.64275: andl $1, %eax 
.64278: pxor %xmm0, %xmm0 
.64282: shrq $1, %rcx 
.64285: orq %rax, %rcx 
.64288: cvtsi2ssq %rcx, %xmm0 
.64293: addss %xmm0, %xmm0 
.64297: jmp .64105 
.64304: mulss %xmm2, %xmm0 
.64308: jmp .64154 
.64320: comiss .114572(%rip), %xmm0 
.64327: jae .64384 
.64329: cvttss2si %xmm0, %rsi 
.64334: movq %rbx, %rdi 
.64337: callq .63344 
.64342: testb %al, %al 
.64344: je .64167 
.64350: xorl %ecx, %ecx 
.64352: movq %r12, %rdx 
.64355: movq %rbp, %rsi 
.64358: movq %rbx, %rdi 
.64361: callq .60416 
.64366: testq %rax, %rax 
.64369: je .63914 
.64375: jmp .19897 
.64384: subss .114572(%rip), %xmm0 
.64392: cvttss2si %xmm0, %rsi 
.64397: btcq $0x3f, %rsi 
.64402: jmp .64334 
.64404: hlt 
