.19360: endbr64 
.19364: bnd jmpq *.143040(%rip) 
.29456: pushq %r12 
.29458: movq %rsi, %r12 
.29461: pushq %rbp 
.29462: movq %rdi, %rbp 
.29465: subq $8, %rsp 
.29469: callq .18272 
.29474: movq %r12, %rsi 
.29477: movq %rbp, %rdi 
.29480: movl $0, (%rax) 
.29486: addq $8, %rsp 
.29490: popq %rbp 
.29491: popq %r12 
.29493: jmp .19360 
.50248: nopl (%rax, %rax) 
.50256: endbr64 
.50260: movl 0xa8(%rdi), %eax 
.50266: movl 0xa8(%rsi), %ecx 
.50272: cmpl $3, %eax 
.50275: sete %dl 
.50278: cmpl $9, %eax 
.50281: sete %al 
.50284: orl %eax, %edx 
.50286: cmpl $3, %ecx 
.50289: sete %al 
.50292: cmpl $9, %ecx 
.50295: sete %cl 
.50298: orb %cl, %al 
.50300: jne .50320 
.50302: testb %dl, %dl 
.50304: jne .50376 
.50306: movl $1, %r8d 
.50312: testb %al, %al 
.50314: je .50324 
.50316: movl %r8d, %eax 
.50319: ret 
.50320: testb %dl, %dl 
.50322: je .50306 
.50324: movq 0x60(%rsi), %rax 
.50328: cmpq %rax, 0x60(%rdi) 
.50332: jg .50376 
.50334: jl .50360 
.50336: movq 0x68(%rsi), %r8 
.50340: subl 0x68(%rdi), %r8d 
.50344: jne .50316 
.50346: movq (%rsi), %rsi 
.50349: movq (%rdi), %rdi 
.50352: jmp .29456 
.50360: movl $1, %r8d 
.50366: movl %r8d, %eax 
.50369: ret 
.50376: movl $0xffffffff, %r8d 
.50382: jmp .50316 
