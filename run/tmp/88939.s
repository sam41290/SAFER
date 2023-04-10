.88939: nopl (%rax, %rax) 
.88944: endbr64 
.88948: pushq %r15 
.88950: movq %rdi, %r15 
.88953: pushq %r14 
.88955: movq %rcx, %r14 
.88958: pushq %r13 
.88960: movq %rdx, %r13 
.88963: movl %esi, %edx 
.88965: xorl %esi, %esi 
.88967: pushq %r12 
.88969: movq %r9, %r12 
.88972: pushq %rbp 
.88973: pushq %rbx 
.88974: subq $0x18, %rsp 
.88978: movq %fs:0x28, %rax 
.88987: movq %rax, 8(%rsp) 
.88992: xorl %eax, %eax 
.88994: movq %rsp, %rcx 
.88997: movl 0x50(%rsp), %ebp 
.89001: callq .90944 
.89006: testl %eax, %eax 
.89008: jne .89152 
.89014: movq (%rsp), %rbx 
.89018: cmpq %r13, %rbx 
.89021: jb .89028 
.89023: cmpq %r14, %rbx 
.89026: jbe .89114 
.89028: callq .18272 
.89033: cmpq $0x40000000, %rbx 
.89040: movq %rax, %r13 
.89043: sbbl %eax, %eax 
.89045: andl $0xffffffd7, %eax 
.89048: addl $0x4b, %eax 
.89051: movl %eax, (%r13) 
.89055: movq %r15, %rdi 
.89058: callq .86080 
.89063: movl (%r13), %esi 
.89067: movq %r12, %rcx 
.89070: leaq .104844(%rip), %rdx 
.89077: movq %rax, %r8 
.89080: movl $0, %eax 
.89085: cmpl $0x16, %esi 
.89088: cmovel %eax, %esi 
.89091: testl %ebp, %ebp 
.89093: movl $1, %eax 
.89098: cmovel %eax, %ebp 
.89101: xorl %eax, %eax 
.89103: movl %ebp, %edi 
.89105: callq .19552 
.89110: movq (%rsp), %rbx 
.89114: movq 8(%rsp), %rax 
.89119: xorq %fs:0x28, %rax 
.89128: jne .89195 
.89130: addq $0x18, %rsp 
.89134: movq %rbx, %rax 
.89137: popq %rbx 
.89138: popq %rbp 
.89139: popq %r12 
.89141: popq %r13 
.89143: popq %r14 
.89145: popq %r15 
.89147: ret 
.89152: movl %eax, %ebx 
.89154: callq .18272 
.89159: movq %rax, %r13 
.89162: cmpl $1, %ebx 
.89165: je .89184 
.89167: cmpl $3, %ebx 
.89170: jne .89055 
.89172: movl $0, (%rax) 
.89178: jmp .89055 
.89184: movl $0x4b, (%rax) 
.89190: jmp .89055 
.89195: hlt 
