.29047: nopw (%rax, %rax) 
.29056: pushq %rbx 
.29057: movq .148400(%rip), %rbx 
.29064: movq %rbx, %rax 
.29067: shrq $1, %rax 
.29070: addq %rbx, %rax 
.29073: cmpq .148376(%rip), %rax 
.29080: ja .29328 
.29086: testq %rbx, %rbx 
.29089: je .29131 
.29091: movq .148384(%rip), %rax 
.29098: movq .148416(%rip), %rdx 
.29105: leaq (%rax, %rbx, 8), %rcx 
.29109: nopl (%rax) 
.29112: movq %rdx, (%rax) 
.29115: addq $8, %rax 
.29119: addq $0xc8, %rdx 
.29126: cmpq %rax, %rcx 
.29129: jne .29112 
.29131: cmpl $-1, .148272(%rip) 
.29138: je .29304 
.29144: leaq .144128(%rip), %rdi 
.29151: callq .19008 
.29156: endbr64 
.29160: movl .148272(%rip), %esi 
.29166: testl %eax, %eax 
.29168: je .29312 
.29174: cmpl $3, %esi 
.29177: je .29422 
.29183: movq .148400(%rip), %r8 
.29190: movq .148384(%rip), %rdi 
.29197: testq %r8, %r8 
.29200: je .29235 
.29202: movq .148416(%rip), %rdx 
.29209: movq %rdi, %rax 
.29212: leaq (%rdi, %r8, 8), %rcx 
.29216: movq %rdx, (%rax) 
.29219: addq $8, %rax 
.29223: addq $0xc8, %rdx 
.29230: cmpq %rcx, %rax 
.29233: jne .29216 
.29235: movl $1, %eax 
.29240: cmpl $4, %esi 
.29243: movl $0, %edx 
.29248: cltq 
.29250: cmovel .148276(%rip), %edx 
.29257: movzbl .148212(%rip), %ecx 
.29264: addl %esi, %edx 
.29266: movq %r8, %rsi 
.29269: leaq (%rax, %rdx, 2), %rdx 
.29273: movzbl .148271(%rip), %eax 
.29280: leaq (%rax, %rdx, 2), %rax 
.29284: leaq (%rcx, %rax, 2), %rdx 
.29288: leaq .139296(%rip), %rax 
.29295: movq (%rax, %rdx, 8), %rdx 
.29299: callq .72000 
.29304: popq %rbx 
.29305: ret 
.29312: movq .148384(%rip), %rdi 
.29319: movq .148400(%rip), %r8 
.29326: jmp .29240 
.29328: movq .148384(%rip), %rdi 
.29335: callq .18128 
.29340: movl $0x18, %edx 
.29345: movq %rdx, %rax 
.29348: mulq %rbx 
.29351: seto %dl 
.29354: testq %rax, %rax 
.29357: movl $1, %eax 
.29362: movzbl %dl, %edx 
.29365: cmovsq %rax, %rdx 
.29369: testq %rdx, %rdx 
.29372: jne .29417 
.29374: leaq (%rbx, %rbx, 2), %rdi 
.29378: shlq $3, %rdi 
.29382: callq .88256 
.29387: movq .148400(%rip), %rbx 
.29394: movq %rax, .148384(%rip) 
.29401: leaq (%rbx, %rbx, 2), %rax 
.29405: movq %rax, .148376(%rip) 
.29412: jmp .29086 
.29417: hlt 
.29422: leaq .99976(%rip), %rcx 
.29429: movl $0xee8, %edx 
.29434: leaq .104372(%rip), %rsi 
.29441: leaq .104381(%rip), %rdi 
.29448: hlt 
