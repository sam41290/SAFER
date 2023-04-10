.31288: nopl (%rax, %rax) 
.31296: testb %dil, %dil 
.31299: je .31336 
.31301: movl %esi, %eax 
.31303: andl $0xf000, %eax 
.31308: cmpl $0x8000, %eax 
.31313: jne .31432 
.31315: xorl %eax, %eax 
.31317: cmpl $3, .148244(%rip) 
.31324: je .31480 
.31330: ret 
.31336: xorl %eax, %eax 
.31338: cmpl $5, %edx 
.31341: je .31330 
.31343: cmpl $3, %edx 
.31346: sete %cl 
.31349: cmpl $9, %edx 
.31352: sete %al 
.31355: orl %eax, %ecx 
.31357: movl $0x2f, %eax 
.31362: testb %cl, %cl 
.31364: jne .31330 
.31366: xorl %eax, %eax 
.31368: cmpl $1, .148244(%rip) 
.31375: je .31330 
.31377: testb %dil, %dil 
.31380: je .31448 
.31382: andl $0xf000, %esi 
.31388: movl $0x40, %eax 
.31393: cmpl $0xa000, %esi 
.31399: je .31520 
.31401: movl $0x7c, %eax 
.31406: cmpl $0x1000, %esi 
.31412: je .31504 
.31414: cmpl $0xc000, %esi 
.31420: sete %al 
.31423: negl %eax 
.31425: andl $0x3d, %eax 
.31428: ret 
.31432: cmpl $0x4000, %eax 
.31437: sete %cl 
.31440: jmp .31357 
.31448: movl $0x40, %eax 
.31453: cmpl $6, %edx 
.31456: je .31528 
.31458: movl $0x7c, %eax 
.31463: cmpl $1, %edx 
.31466: je .31512 
.31468: cmpl $7, %edx 
.31471: sete %al 
.31474: jmp .31423 
.31480: andl $0x49, %esi 
.31483: cmpl $1, %esi 
.31486: sbbl %eax, %eax 
.31488: notl %eax 
.31490: andl $0x2a, %eax 
.31493: ret 
.31504: ret 
.31512: ret 
.31520: ret 
.31528: ret 
