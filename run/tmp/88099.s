.19024: endbr64 
.19028: bnd jmpq *.142872(%rip) 
.88099: nopw %cs:(%rax, %rax) 
.88110: nop 
.88112: endbr64 
.88116: pushq %rbp 
.88117: movl $5, %edx 
.88122: leaq .117186(%rip), %rsi 
.88129: xorl %edi, %edi 
.88131: callq .18592 
.88136: leaq .117207(%rip), %rdx 
.88143: movl $1, %edi 
.88148: movq %rax, %rsi 
.88151: xorl %eax, %eax 
.88153: callq .19472 
.88158: movl $5, %edx 
.88163: leaq .117229(%rip), %rsi 
.88170: xorl %edi, %edi 
.88172: callq .18592 
.88177: leaq .113496(%rip), %rcx 
.88184: movl $1, %edi 
.88189: leaq .104747(%rip), %rdx 
.88196: movq %rax, %rsi 
.88199: xorl %eax, %eax 
.88201: callq .19472 
.88206: movq .144008(%rip), %rbp 
.88213: xorl %edi, %edi 
.88215: leaq .117792(%rip), %rsi 
.88222: movl $5, %edx 
.88227: callq .18592 
.88232: movq %rbp, %rsi 
.88235: popq %rbp 
.88236: movq %rax, %rdi 
.88239: jmp .19024 
