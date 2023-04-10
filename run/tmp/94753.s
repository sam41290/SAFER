.94753: nopw %cs:(%rax, %rax) 
.94763: nopl (%rax, %rax) 
.94768: endbr64 
.94772: cmpl $0x26, %edi 
.94775: je .94816 
.94777: jg .94800 
.94779: xorl %eax, %eax 
.94781: cmpl $0x10, %edi 
.94784: je .94818 
.94786: cmpl $0x16, %edi 
.94789: setne %al 
.94792: ret 
.94800: cmpl $0x5f, %edi 
.94803: setne %al 
.94806: ret 
.94816: xorl %eax, %eax 
.94818: ret 
