.58921: nopl (%rax) 
.58928: movq (%rdi), %rdx 
.58931: movzbl (%rdx), %eax 
.58934: testb %al, %al 
.58936: je .59088 
.58942: xorl %ecx, %ecx 
.58944: xorl %r8d, %r8d 
.58947: xorl %esi, %esi 
.58949: jmp .58986 
.58960: cmpb $0x5a, %al 
.58962: jg .59032 
.58964: xorl %ecx, %ecx 
.58966: cmpb $0x41, %al 
.58968: cmovlq %rsi, %r8 
.58972: addq $1, %rdx 
.58976: movq %rdx, (%rdi) 
.58979: movzbl (%rdx), %eax 
.58982: testb %al, %al 
.58984: je .59025 
.58986: testb %cl, %cl 
.58988: jne .58960 
.58990: cmpb $0x2e, %al 
.58992: je .59072 
.58994: cmpb $0x5a, %al 
.58996: jg .59056 
.58998: cmpb $0x40, %al 
.59000: jg .58972 
.59002: subl $0x30, %eax 
.59005: cmpb $0xa, %al 
.59007: cmovaeq %rsi, %r8 
.59011: addq $1, %rdx 
.59015: movq %rdx, (%rdi) 
.59018: movzbl (%rdx), %eax 
.59021: testb %al, %al 
.59023: jne .58986 
.59025: movq %r8, %rax 
.59028: ret 
.59032: leal -0x61(%rax), %r9d 
.59036: xorl %ecx, %ecx 
.59038: cmpb $0x19, %r9b 
.59042: jbe .58972 
.59044: cmpb $0x7e, %al 
.59046: cmovneq %rsi, %r8 
.59050: jmp .58972 
.59056: leal -0x61(%rax), %r9d 
.59060: cmpb $0x19, %r9b 
.59064: ja .59044 
.59066: jmp .58972 
.59072: testq %r8, %r8 
.59075: movl $1, %ecx 
.59080: cmoveq %rdx, %r8 
.59084: jmp .58972 
.59088: xorl %r8d, %r8d 
.59091: movq %r8, %rax 
.59094: ret 
