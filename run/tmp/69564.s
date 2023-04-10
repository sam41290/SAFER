.69564: nopl (%rax) 
.69568: endbr64 
.69572: movb $0, 0x14(%rsi) 
.69576: leaq 0x14(%rsi), %r8 
.69580: movabsq $0xcccccccccccccccd, %rcx 
.69590: nopw %cs:(%rax, %rax) 
.69600: movq %rdi, %rax 
.69603: movq %rdi, %rsi 
.69606: subq $1, %r8 
.69610: mulq %rcx 
.69613: shrq $3, %rdx 
.69617: leaq (%rdx, %rdx, 4), %rax 
.69621: addq %rax, %rax 
.69624: subq %rax, %rsi 
.69627: movq %rsi, %rax 
.69630: addl $0x30, %eax 
.69633: movb %al, (%r8) 
.69636: movq %rdi, %rax 
.69639: movq %rdx, %rdi 
.69642: cmpq $9, %rax 
.69646: ja .69600 
.69648: movq %r8, %rax 
.69651: ret 
