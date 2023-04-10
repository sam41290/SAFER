.18768: endbr64 
.18772: bnd jmpq *.142744(%rip) 
.30177: nopw %cs:(%rax, %rax) 
.30188: nopl (%rax) 
.30192: pushq %r12 
.30194: pushq %rbp 
.30195: pushq %rbx 
.30196: movq 0x18(%rsi), %rax 
.30200: movq 0x10(%rsi), %rbx 
.30204: movq %rax, %rbp 
.30207: subq %rbx, %rbp 
.30210: cmpq $7, %rbp 
.30214: jbe .30359 
.30220: cmpq %rbx, %rax 
.30223: je .30364 
.30229: movq 0x30(%rsi), %rdx 
.30233: movq 8(%rsi), %rcx 
.30237: leaq .104407(%rip), %r12 
.30244: addq %rdx, %rax 
.30247: notq %rdx 
.30250: andq %rdx, %rax 
.30253: movq 0x20(%rsi), %rdx 
.30257: movq %rax, %r8 
.30260: movq %rdx, %r9 
.30263: subq %rcx, %r8 
.30266: subq %rcx, %r9 
.30269: cmpq %r9, %r8 
.30272: cmovaq %rdx, %rax 
.30276: andq $0xfffffffffffffff8, %rbp 
.30280: addq %rbx, %rbp 
.30283: movq %rax, 0x18(%rsi) 
.30287: movq %rax, 0x10(%rsi) 
.30291: movq .144008(%rip), %rsi 
.30298: callq .19024 
.30303: nop 
.30304: movq (%rbx), %rdx 
.30307: movq %r12, %rsi 
.30310: movl $1, %edi 
.30315: xorl %eax, %eax 
.30317: addq $8, %rbx 
.30321: callq .19472 
.30326: cmpq %rbp, %rbx 
.30329: jne .30304 
.30331: movq .144008(%rip), %rdi 
.30338: movq 0x28(%rdi), %rax 
.30342: cmpq 0x30(%rdi), %rax 
.30346: jae .30373 
.30348: leaq 1(%rax), %rdx 
.30352: movq %rdx, 0x28(%rdi) 
.30356: movb $0xa, (%rax) 
.30359: popq %rbx 
.30360: popq %rbp 
.30361: popq %r12 
.30363: ret 
.30364: orb $2, 0x50(%rsi) 
.30368: jmp .30229 
.30373: popq %rbx 
.30374: movl $0xa, %esi 
.30379: popq %rbp 
.30380: popq %r12 
.30382: jmp .18768 
