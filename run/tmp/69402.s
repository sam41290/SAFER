.69402: nopw (%rax, %rax) 
.69408: endbr64 
.69412: movb $0, 0x14(%rsi) 
.69416: leaq 0x14(%rsi), %r8 
.69420: movabsq $0xcccccccccccccccd, %rcx 
.69430: testq %rdi, %rdi 
.69433: js .69488 
.69435: nopl (%rax, %rax) 
.69440: movq %rdi, %rax 
.69443: subq $1, %r8 
.69447: mulq %rcx 
.69450: shrq $3, %rdx 
.69454: leaq (%rdx, %rdx, 4), %rax 
.69458: addq %rax, %rax 
.69461: subq %rax, %rdi 
.69464: addl $0x30, %edi 
.69467: movb %dil, (%r8) 
.69470: movq %rdx, %rdi 
.69473: testq %rdx, %rdx 
.69476: jne .69440 
.69478: movq %r8, %rax 
.69481: ret 
.69488: movabsq $0x6666666666666667, %r9 
.69498: movl $0x30, %esi 
.69503: nop 
.69504: movq %rdi, %rax 
.69507: movq %r8, %rcx 
.69510: subq $1, %r8 
.69514: imulq %r9 
.69517: movq %rdi, %rax 
.69520: sarq $0x3f, %rax 
.69524: sarq $2, %rdx 
.69528: subq %rax, %rdx 
.69531: leaq (%rdx, %rdx, 4), %rax 
.69535: leal (%rsi, %rax, 2), %eax 
.69538: subl %edi, %eax 
.69540: movq %rdx, %rdi 
.69543: movb %al, (%r8) 
.69546: testq %rdx, %rdx 
.69549: jne .69504 
.69551: movb $0x2d, -1(%r8) 
.69556: leaq -2(%rcx), %r8 
.69560: movq %r8, %rax 
.69563: ret 
