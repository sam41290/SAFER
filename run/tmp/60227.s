.60227: nopw %cs:(%rax, %rax) 
.60237: nopl (%rax) 
.60240: endbr64 
.60244: xorl %esi, %esi 
.60246: subq $8, %rsp 
.60250: callq .19456 
.60255: movq %rax, %rsi 
.60258: movl $1, %eax 
.60263: testq %rsi, %rsi 
.60266: je .60297 
.60268: cmpb $0x43, (%rsi) 
.60271: je .60304 
.60273: movl $6, %ecx 
.60278: leaq .114396(%rip), %rdi 
.60285: repe cmpsb (%rdi), (%rsi) 
.60287: seta %al 
.60290: sbbb $0, %al 
.60292: testb %al, %al 
.60294: setne %al 
.60297: addq $8, %rsp 
.60301: ret 
.60304: xorl %eax, %eax 
.60306: cmpb $0, 1(%rsi) 
.60310: jne .60273 
.60312: addq $8, %rsp 
.60316: ret 
