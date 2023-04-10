.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.50822: nopw %cs:(%rax, %rax) 
.50832: endbr64 
.50836: movl 0xa8(%rdi), %eax 
.50842: movq %rsi, %rdx 
.50845: movl 0xa8(%rsi), %esi 
.50851: cmpl $3, %eax 
.50854: sete %cl 
.50857: cmpl $9, %eax 
.50860: sete %al 
.50863: orl %eax, %ecx 
.50865: cmpl $3, %esi 
.50868: sete %al 
.50871: cmpl $9, %esi 
.50874: sete %sil 
.50878: orb %sil, %al 
.50881: jne .50904 
.50883: testb %cl, %cl 
.50885: jne .50960 
.50887: movl $1, %r8d 
.50893: testb %al, %al 
.50895: je .50908 
.50897: movl %r8d, %eax 
.50900: ret 
.50904: testb %cl, %cl 
.50906: je .50887 
.50908: movq 0x60(%rdi), %rax 
.50912: cmpq %rax, 0x60(%rdx) 
.50916: jg .50960 
.50918: jl .50944 
.50920: movq 0x68(%rdi), %r8 
.50924: subl 0x68(%rdx), %r8d 
.50928: jne .50897 
.50930: movq (%rdi), %rsi 
.50933: movq (%rdx), %rdi 
.50936: jmp .19072 
.50944: movl $1, %r8d 
.50950: movl %r8d, %eax 
.50953: ret 
.50960: movl $0xffffffff, %r8d 
.50966: jmp .50897 
