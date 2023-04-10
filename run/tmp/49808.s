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
.49808: endbr64 
.49812: movl 0xa8(%rdi), %eax 
.49818: movl 0xa8(%rsi), %ecx 
.49824: cmpl $3, %eax 
.49827: sete %dl 
.49830: cmpl $9, %eax 
.49833: sete %al 
.49836: orl %eax, %edx 
.49838: cmpl $3, %ecx 
.49841: sete %al 
.49844: cmpl $9, %ecx 
.49847: sete %cl 
.49850: orb %cl, %al 
.49852: jne .49872 
.49854: testb %dl, %dl 
.49856: jne .49944 
.49858: movl $1, %r8d 
.49864: testb %al, %al 
.49866: je .49876 
.49868: movl %r8d, %eax 
.49871: ret 
.49872: testb %dl, %dl 
.49874: je .49858 
.49876: movq 0x80(%rsi), %rax 
.49883: cmpq %rax, 0x80(%rdi) 
.49890: jg .49944 
.49892: jl .49928 
.49894: movq 0x88(%rsi), %r8 
.49901: subl 0x88(%rdi), %r8d 
.49908: jne .49868 
.49910: movq (%rsi), %rsi 
.49913: movq (%rdi), %rdi 
.49916: jmp .29456 
.49921: nopl (%rax) 
.49928: movl $1, %r8d 
.49934: movl %r8d, %eax 
.49937: ret 
.49938: nopw (%rax, %rax) 
.49944: movl $0xffffffff, %r8d 
.49950: jmp .49868 
