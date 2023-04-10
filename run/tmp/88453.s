.88352: endbr64 
.88356: pushq %rbx 
.88357: movq %rsi, %rbx 
.88360: testq %rsi, %rsi 
.88363: jne .88370 
.88365: testq %rdi, %rdi 
.88368: jne .88400 
.88370: movq %rbx, %rsi 
.88373: callq .19424 
.88378: testq %rax, %rax 
.88381: jne .88388 
.88383: testq %rbx, %rbx 
.88386: jne .88409 
.88388: popq %rbx 
.88389: ret 
.88400: callq .18128 
.88405: xorl %eax, %eax 
.88407: popq %rbx 
.88408: ret 
.88409: hlt 
.88453: nopw %cs:(%rax, %rax) 
.88464: endbr64 
.88468: movq %rsi, %r9 
.88471: movq %rdx, %r8 
.88474: movq (%rsi), %rsi 
.88477: testq %rdi, %rdi 
.88480: je .88528 
.88482: movabsq $0x5555555555555554, %rax 
.88492: xorl %edx, %edx 
.88494: divq %r8 
.88497: cmpq %rsi, %rax 
.88500: jbe .88555 
.88502: movq %rsi, %rax 
.88505: shrq $1, %rax 
.88508: leaq 1(%rax, %rsi), %rsi 
.88513: movq %rsi, (%r9) 
.88516: imulq %r8, %rsi 
.88520: jmp .88352 
.88528: testq %rsi, %rsi 
.88531: je .88568 
.88533: movq %rsi, %rax 
.88536: mulq %r8 
.88539: seto %dl 
.88542: movzbl %dl, %edx 
.88545: testq %rax, %rax 
.88548: js .88555 
.88550: testq %rdx, %rdx 
.88553: je .88513 
.88555: pushq %rax 
.88556: hlt 
.88568: xorl %edx, %edx 
.88570: movl $0x80, %eax 
.88575: xorl %ecx, %ecx 
.88577: divq %r8 
.88580: cmpq $0x80, %r8 
.88587: seta %cl 
.88590: leaq (%rcx, %rax), %rsi 
.88594: jmp .88533 
