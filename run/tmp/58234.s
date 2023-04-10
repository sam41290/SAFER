.58234: nopw (%rax, %rax) 
.58240: endbr64 
.58244: movl %edi, %edx 
.58246: movl $0x2d, %eax 
.58251: andl $0xf000, %edx 
.58257: cmpl $0x8000, %edx 
.58263: je .58349 
.58265: movl $0x64, %eax 
.58270: cmpl $0x4000, %edx 
.58276: je .58349 
.58278: movl $0x62, %eax 
.58283: cmpl $0x6000, %edx 
.58289: je .58349 
.58291: movl $0x63, %eax 
.58296: cmpl $0x2000, %edx 
.58302: je .58349 
.58304: movl $0x6c, %eax 
.58309: cmpl $0xa000, %edx 
.58315: je .58349 
.58317: movl $0x70, %eax 
.58322: cmpl $0x1000, %edx 
.58328: je .58349 
.58330: cmpl $0xc000, %edx 
.58336: movl $0x73, %eax 
.58341: movl $0x3f, %edx 
.58346: cmovnel %edx, %eax 
.58349: movb %al, (%rsi) 
.58351: movl %edi, %eax 
.58353: andl $0x100, %eax 
.58358: cmpl $1, %eax 
.58361: sbbl %eax, %eax 
.58363: andl $0xffffffbb, %eax 
.58366: addl $0x72, %eax 
.58369: movb %al, 1(%rsi) 
.58372: movl %edi, %eax 
.58374: andl $0x80, %eax 
.58379: cmpl $1, %eax 
.58382: sbbl %eax, %eax 
.58384: andl $0xffffffb6, %eax 
.58387: addl $0x77, %eax 
.58390: movb %al, 2(%rsi) 
.58393: movl %edi, %eax 
.58395: andl $0x40, %eax 
.58398: cmpl $1, %eax 
.58401: sbbl %eax, %eax 
.58403: testl $0x800, %edi 
.58409: je .58568 
.58415: andl $0xffffffe0, %eax 
.58418: addl $0x73, %eax 
.58421: movb %al, 3(%rsi) 
.58424: movl %edi, %eax 
.58426: andl $0x20, %eax 
.58429: cmpl $1, %eax 
.58432: sbbl %eax, %eax 
.58434: andl $0xffffffbb, %eax 
.58437: addl $0x72, %eax 
.58440: movb %al, 4(%rsi) 
.58443: movl %edi, %eax 
.58445: andl $0x10, %eax 
.58448: cmpl $1, %eax 
.58451: sbbl %eax, %eax 
.58453: andl $0xffffffb6, %eax 
.58456: addl $0x77, %eax 
.58459: movb %al, 5(%rsi) 
.58462: movl %edi, %eax 
.58464: andl $8, %eax 
.58467: cmpl $1, %eax 
.58470: sbbl %eax, %eax 
.58472: testl $0x400, %edi 
.58478: je .58584 
.58480: andl $0xffffffe0, %eax 
.58483: addl $0x73, %eax 
.58486: movb %al, 6(%rsi) 
.58489: movl %edi, %eax 
.58491: andl $4, %eax 
.58494: cmpl $1, %eax 
.58497: sbbl %eax, %eax 
.58499: andl $0xffffffbb, %eax 
.58502: addl $0x72, %eax 
.58505: movb %al, 7(%rsi) 
.58508: movl %edi, %eax 
.58510: andl $2, %eax 
.58513: cmpl $1, %eax 
.58516: sbbl %eax, %eax 
.58518: andl $0xffffffb6, %eax 
.58521: addl $0x77, %eax 
.58524: movb %al, 8(%rsi) 
.58527: movl %edi, %eax 
.58529: andl $1, %eax 
.58532: cmpl $1, %eax 
.58535: sbbl %eax, %eax 
.58537: andl $0x200, %edi 
.58543: je .58592 
.58545: andl $0xffffffe0, %eax 
.58548: addl $0x74, %eax 
.58551: movb %al, 9(%rsi) 
.58554: movl $0x20, %eax 
.58559: movw %ax, 0xa(%rsi) 
.58563: ret 
.58568: andl $0xffffffb5, %eax 
.58571: addl $0x78, %eax 
.58574: jmp .58421 
.58584: andl $0xffffffb5, %eax 
.58587: addl $0x78, %eax 
.58590: jmp .58486 
.58592: andl $0xffffffb5, %eax 
.58595: addl $0x78, %eax 
.58598: movb %al, 9(%rsi) 
.58601: movl $0x20, %eax 
.58606: movw %ax, 0xa(%rsi) 
.58610: ret 
