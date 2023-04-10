.57650: nopw %cs:(%rax, %rax) 
.57660: nopl (%rax) 
.57664: endbr64 
.57668: movzbl (%rdi), %edx 
.57671: movq %rdi, %rax 
.57674: cmpb $0x2f, %dl 
.57677: jne .57693 
.57679: nop 
.57680: movzbl 1(%rax), %edx 
.57684: addq $1, %rax 
.57688: cmpb $0x2f, %dl 
.57691: je .57680 
.57693: testb %dl, %dl 
.57695: je .57756 
.57697: movq %rax, %rcx 
.57700: xorl %esi, %esi 
.57702: jmp .57734 
.57712: testb %sil, %sil 
.57715: je .57722 
.57717: movq %rcx, %rax 
.57720: xorl %esi, %esi 
.57722: movzbl 1(%rcx), %edx 
.57726: addq $1, %rcx 
.57730: testb %dl, %dl 
.57732: je .57756 
.57734: cmpb $0x2f, %dl 
.57737: jne .57712 
.57739: movzbl 1(%rcx), %edx 
.57743: addq $1, %rcx 
.57747: movl $1, %esi 
.57752: testb %dl, %dl 
.57754: jne .57734 
.57756: ret 
