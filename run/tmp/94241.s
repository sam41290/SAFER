.18816: endbr64 
.18820: bnd jmpq *.142768(%rip) 
.94241: nopw %cs:(%rax, %rax) 
.94252: nopl (%rax) 
.94256: endbr64 
.94260: pushq %r14 
.94262: movq %rsi, %r14 
.94265: pushq %r13 
.94267: pushq %r12 
.94269: pushq %rbp 
.94270: movq %rdx, %rbp 
.94273: subq $8, %rsp 
.94277: testq %rdi, %rdi 
.94280: je .94400 
.94282: movq %rdi, %r12 
.94285: callq .94032 
.94290: movq %rax, %r13 
.94293: testq %rax, %rax 
.94296: je .94366 
.94298: movq %rbp, %rsi 
.94301: movq %r14, %rdi 
.94304: callq .18304 
.94309: testq %rax, %rax 
.94312: je .94352 
.94314: movq %rbp, %rsi 
.94317: movq %r12, %rdi 
.94320: callq .93680 
.94325: testb %al, %al 
.94327: je .94352 
.94329: cmpq $1, %r13 
.94333: jne .94384 
.94335: addq $8, %rsp 
.94339: movq %rbp, %rax 
.94342: popq %rbp 
.94343: popq %r12 
.94345: popq %r13 
.94347: popq %r14 
.94349: ret 
.94352: cmpq $1, %r13 
.94356: je .94366 
.94358: movq %r13, %rdi 
.94361: callq .93424 
.94366: addq $8, %rsp 
.94370: xorl %eax, %eax 
.94372: popq %rbp 
.94373: popq %r12 
.94375: popq %r13 
.94377: popq %r14 
.94379: ret 
.94384: movq %r13, %rdi 
.94387: callq .93424 
.94392: testb %al, %al 
.94394: jne .94335 
.94396: jmp .94366 
.94400: addq $8, %rsp 
.94404: movq %r14, %rdi 
.94407: movq %rdx, %rsi 
.94410: popq %rbp 
.94411: popq %r12 
.94413: popq %r13 
.94415: popq %r14 
.94417: jmp .18816 
