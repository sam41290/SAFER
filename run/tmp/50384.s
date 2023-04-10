.19072: endbr64 
.19076: bnd jmpq *.142896(%rip) 
.50384: endbr64 
.50388: movq 0x70(%rsi), %rax 
.50392: cmpq %rax, 0x70(%rdi) 
.50396: jg .50432 
.50398: jl .50424 
.50400: movq 0x78(%rsi), %rax 
.50404: subl 0x78(%rdi), %eax 
.50407: jne .50429 
.50409: movq (%rsi), %rsi 
.50412: movq (%rdi), %rdi 
.50415: jmp .19072 
.50420: nopl (%rax) 
.50424: movl $1, %eax 
.50429: ret 
.50430: nop 
.50432: movl $0xffffffff, %eax 
.50437: ret 
