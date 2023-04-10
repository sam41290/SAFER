.19912: hlt 
.84281: nopl (%rax) 
.84288: endbr64 
.84292: subq $8, %rsp 
.84296: leaq .148768(%rip), %rax 
.84303: testq %rdi, %rdi 
.84306: cmoveq %rax, %rdi 
.84310: movl $0xa, (%rdi) 
.84316: testq %rsi, %rsi 
.84319: je .19912 
.84325: testq %rdx, %rdx 
.84328: je .19912 
.84334: movq %rsi, 0x28(%rdi) 
.84338: movq %rdx, 0x30(%rdi) 
.84342: addq $8, %rsp 
.84346: ret 
