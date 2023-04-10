.94422: nopw %cs:(%rax, %rax) 
.94432: endbr64 
.94436: pushq %r13 
.94438: pushq %r12 
.94440: pushq %rbp 
.94441: movq %rsi, %rbp 
.94444: subq $0x50, %rsp 
.94448: movq %fs:0x28, %rax 
.94457: movq %rax, 0x48(%rsp) 
.94462: xorl %eax, %eax 
.94464: testq %rdi, %rdi 
.94467: je .94720 
.94473: movq %rdi, %r12 
.94476: callq .94032 
.94481: movq %rax, %r13 
.94484: testq %rax, %rax 
.94487: je .94736 
.94493: movq %rbp, %rdi 
.94496: callq .19376 
.94501: movq %rax, 8(%rsp) 
.94506: cmpq $-1, %rax 
.94510: je .94600 
.94512: movq %rbp, %rsi 
.94515: movq %r12, %rdi 
.94518: callq .93680 
.94523: testb %al, %al 
.94525: jne .94536 
.94527: movq $-1, 8(%rsp) 
.94536: cmpq $1, %r13 
.94540: je .94558 
.94542: movq %r13, %rdi 
.94545: callq .93424 
.94550: testb %al, %al 
.94552: je .94736 
.94558: movq 8(%rsp), %rax 
.94563: movq 0x48(%rsp), %rcx 
.94568: xorq %fs:0x28, %rcx 
.94577: jne .94748 
.94583: addq $0x50, %rsp 
.94587: popq %rbp 
.94588: popq %r12 
.94590: popq %r13 
.94592: ret 
.94600: leaq 0x10(%rsp), %rsi 
.94605: leaq 8(%rsp), %rdi 
.94610: callq .18304 
.94615: testq %rax, %rax 
.94618: je .94536 
.94620: movl 0x20(%rbp), %eax 
.94623: movl 0x30(%rsp), %edx 
.94627: testl %eax, %eax 
.94629: sete %sil 
.94633: testl %edx, %edx 
.94635: sete %cl 
.94638: cmpb %cl, %sil 
.94641: je .94651 
.94643: testl %eax, %eax 
.94645: js .94651 
.94647: testl %edx, %edx 
.94649: jns .94536 
.94651: movl 0x10(%rbp), %eax 
.94654: movl 0x14(%rbp), %edx 
.94657: xorl 0x20(%rsp), %eax 
.94661: xorl 0x24(%rsp), %edx 
.94665: orl %edx, %eax 
.94667: movl 0xc(%rbp), %edx 
.94670: xorl 0x1c(%rsp), %edx 
.94674: orl %edx, %eax 
.94676: movl 8(%rbp), %edx 
.94679: xorl 0x18(%rsp), %edx 
.94683: orl %edx, %eax 
.94685: movl 4(%rbp), %edx 
.94688: xorl 0x14(%rsp), %edx 
.94692: orl %edx, %eax 
.94694: movl (%rbp), %edx 
.94697: xorl 0x10(%rsp), %edx 
.94701: orl %edx, %eax 
.94703: je .94512 
.94709: jmp .94536 
.94720: movq %rsi, %rdi 
.94723: callq .19488 
.94728: jmp .94563 
.94736: movq $-1, %rax 
.94743: jmp .94563 
.94748: hlt 
