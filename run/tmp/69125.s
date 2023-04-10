.69125: nopw %cs:(%rax, %rax) 
.69136: endbr64 
.69140: pushq %r12 
.69142: pushq %rbp 
.69143: movq %rdi, %rbp 
.69146: pushq %rbx 
.69147: movq .148456(%rip), %rbx 
.69154: testq %rbx, %rbx 
.69157: je .69216 
.69159: movzbl (%rdi), %r12d 
.69163: jmp .69177 
.69168: movq 8(%rbx), %rbx 
.69172: testq %rbx, %rbx 
.69175: je .69216 
.69177: cmpb %r12b, 0x10(%rbx) 
.69181: jne .69168 
.69183: leaq 0x10(%rbx), %rdi 
.69187: movq %rbp, %rsi 
.69190: callq .19072 
.69195: testl %eax, %eax 
.69197: jne .69168 
.69199: movq %rbx, %r12 
.69202: popq %rbx 
.69203: popq %rbp 
.69204: movq %r12, %rax 
.69207: popq %r12 
.69209: ret 
.69216: movq .148448(%rip), %rbx 
.69223: testq %rbx, %rbx 
.69226: je .69288 
.69228: movzbl (%rbp), %r12d 
.69233: jmp .69249 
.69240: movq 8(%rbx), %rbx 
.69244: testq %rbx, %rbx 
.69247: je .69288 
.69249: cmpb %r12b, 0x10(%rbx) 
.69253: jne .69240 
.69255: leaq 0x10(%rbx), %rdi 
.69259: movq %rbp, %rsi 
.69262: callq .19072 
.69267: testl %eax, %eax 
.69269: jne .69240 
.69271: xorl %r12d, %r12d 
.69274: popq %rbx 
.69275: popq %rbp 
.69276: movq %r12, %rax 
.69279: popq %r12 
.69281: ret 
.69288: movq %rbp, %rdi 
.69291: callq .19184 
.69296: movq %rbp, %rdi 
.69299: movq %rax, %r12 
.69302: callq .18624 
.69307: leaq 0x18(%rax), %rdi 
.69311: andq $0xfffffffffffffff8, %rdi 
.69315: callq .88256 
.69320: movq %rbp, %rsi 
.69323: leaq 0x10(%rax), %rdi 
.69327: movq %rax, %rbx 
.69330: callq .18336 
.69335: testq %r12, %r12 
.69338: je .69376 
.69340: movl 0x10(%r12), %eax 
.69345: movl %eax, (%rbx) 
.69347: movq .148456(%rip), %rax 
.69354: movq %rbx, .148456(%rip) 
.69361: movq %rax, 8(%rbx) 
.69365: jmp .69199 
.69376: movq .148448(%rip), %rax 
.69383: movq %rbx, .148448(%rip) 
.69390: movq %rax, 8(%rbx) 
.69394: movq %r12, %rax 
.69397: popq %rbx 
.69398: popq %rbp 
.69399: popq %r12 
.69401: ret 
