.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.52140: nopl (%rax) 
.52144: endbr64 
.52148: pushq %r13 
.52150: pushq %r12 
.52152: pushq %rbp 
.52153: pushq %rbx 
.52154: movq %rsi, %rbx 
.52157: subq $8, %rsp 
.52161: movl 0xa8(%rdi), %eax 
.52167: movl 0xa8(%rsi), %ecx 
.52173: cmpl $3, %eax 
.52176: sete %dl 
.52179: cmpl $9, %eax 
.52182: sete %al 
.52185: orl %eax, %edx 
.52187: cmpl $3, %ecx 
.52190: sete %al 
.52193: cmpl $9, %ecx 
.52196: sete %cl 
.52199: orb %cl, %al 
.52201: jne .52240 
.52203: testb %dl, %dl 
.52205: jne .52368 
.52211: movl $1, %r8d 
.52217: testb %al, %al 
.52219: je .52244 
.52221: addq $8, %rsp 
.52225: movl %r8d, %eax 
.52228: popq %rbx 
.52229: popq %rbp 
.52230: popq %r12 
.52232: popq %r13 
.52234: ret 
.52240: testb %dl, %dl 
.52242: je .52211 
.52244: movq (%rdi), %r12 
.52247: movl $0x2e, %esi 
.52252: movq %r12, %rdi 
.52255: callq .18784 
.52260: movq (%rbx), %r13 
.52263: movl $0x2e, %esi 
.52268: movq %rax, %rbp 
.52271: movq %r13, %rdi 
.52274: callq .18784 
.52279: movq %rax, %rsi 
.52282: testq %rax, %rax 
.52285: je .52344 
.52287: testq %rbp, %rbp 
.52290: leaq .104446(%rip), %rax 
.52297: cmoveq %rax, %rbp 
.52301: movq %rbp, %rdi 
.52304: callq .19072 
.52309: movl %eax, %r8d 
.52312: testl %eax, %eax 
.52314: jne .52221 
.52316: addq $8, %rsp 
.52320: movq %r13, %rsi 
.52323: movq %r12, %rdi 
.52326: popq %rbx 
.52327: popq %rbp 
.52328: popq %r12 
.52330: popq %r13 
.52332: jmp .19072 
.52344: leaq .104446(%rip), %rsi 
.52351: testq %rbp, %rbp 
.52354: jne .52301 
.52356: jmp .52316 
.52368: movl $0xffffffff, %r8d 
.52374: jmp .52221 
