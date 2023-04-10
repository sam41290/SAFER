.57797: nopw %cs:(%rax, %rax) 
.57807: nop 
.57808: endbr64 
.57812: movl 0x18(%rsi), %eax 
.57815: andl $0xf000, %eax 
.57820: cmpl $0xa000, %eax 
.57825: jne .57840 
.57827: xorl %eax, %eax 
.57829: ret 
.57840: pushq %rbp 
.57841: xorl %ecx, %ecx 
.57843: xorl %edx, %edx 
.57845: movq %rdi, %rbp 
.57848: pushq %rbx 
.57849: movq %rsi, %rbx 
.57852: leaq .114347(%rip), %rsi 
.57859: subq $8, %rsp 
.57863: callq .19648 
.57868: testq %rax, %rax 
.57871: js .57888 
.57873: je .57920 
.57875: addq $8, %rsp 
.57879: movl $1, %eax 
.57884: popq %rbx 
.57885: popq %rbp 
.57886: ret 
.57888: callq .18272 
.57893: movl (%rax), %edi 
.57895: cmpl $0x3d, %edi 
.57898: je .57920 
.57900: callq .94768 
.57905: addq $8, %rsp 
.57909: movzbl %al, %eax 
.57912: popq %rbx 
.57913: popq %rbp 
.57914: negl %eax 
.57916: ret 
.57920: movl 0x18(%rbx), %eax 
.57923: andl $0xf000, %eax 
.57928: cmpl $0x4000, %eax 
.57933: je .57952 
.57935: xorl %eax, %eax 
.57937: addq $8, %rsp 
.57941: popq %rbx 
.57942: popq %rbp 
.57943: ret 
.57952: xorl %ecx, %ecx 
.57954: xorl %edx, %edx 
.57956: leaq .114371(%rip), %rsi 
.57963: movq %rbp, %rdi 
.57966: callq .19648 
.57971: testq %rax, %rax 
.57974: js .57984 
.57976: jne .57875 
.57978: xorl %eax, %eax 
.57980: jmp .57937 
.57984: callq .18272 
.57989: movl (%rax), %edi 
.57991: cmpl $0x3d, %edi 
.57994: jne .57900 
.57996: jmp .57935 
