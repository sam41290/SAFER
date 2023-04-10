.18496: endbr64 
.18500: bnd jmpq *.142608(%rip) 
.19584: endbr64 
.19588: bnd jmpq *.143152(%rip) 
.93318: nopw %cs:(%rax, %rax) 
.93328: movq %rdi, %rsi 
.93331: testq %rdi, %rdi 
.93334: je .93360 
.93336: movl $1, %edx 
.93341: leaq .105200(%rip), %rdi 
.93348: jmp .18496 
.93360: leaq .105200(%rip), %rdi 
.93367: jmp .19584 
