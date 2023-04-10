.89237: nopw %cs:(%rax, %rax) 
.89247: nop 
.89248: endbr64 
.89252: pushq %r12 
.89254: xorl %esi, %esi 
.89256: xorl %edi, %edi 
.89258: callq .18944 
.89263: movq %rax, %r12 
.89266: testq %rax, %rax 
.89269: je .89280 
.89271: movq %r12, %rax 
.89274: popq %r12 
.89276: ret 
.89280: callq .18272 
.89285: cmpl $0xc, (%rax) 
.89288: jne .89271 
.89290: hlt 
