.19360: endbr64 
.19364: bnd jmpq *.143040(%rip) 
.29456: pushq %r12 
.29458: movq %rsi, %r12 
.29461: pushq %rbp 
.29462: movq %rdi, %rbp 
.29465: subq $8, %rsp 
.29469: callq .18272 
.29474: movq %r12, %rsi 
.29477: movq %rbp, %rdi 
.29480: movl $0, (%rax) 
.29486: addq $8, %rsp 
.29490: popq %rbp 
.29491: popq %r12 
.29493: jmp .19360 
.49952: endbr64 
.49956: movl 0xa8(%rdi), %eax 
.49962: movq %rsi, %rdx 
.49965: movl 0xa8(%rsi), %esi 
.49971: cmpl $3, %eax 
.49974: sete %cl 
.49977: cmpl $9, %eax 
.49980: sete %al 
.49983: orl %eax, %ecx 
.49985: cmpl $3, %esi 
.49988: sete %al 
.49991: cmpl $9, %esi 
.49994: sete %sil 
.49998: orb %sil, %al 
.50001: jne .50024 
.50003: testb %cl, %cl 
.50005: jne .50080 
.50007: movl $1, %r8d 
.50013: testb %al, %al 
.50015: je .50028 
.50017: movl %r8d, %eax 
.50020: ret 
.50021: nopl (%rax) 
.50024: testb %cl, %cl 
.50026: je .50007 
.50028: movq 0x70(%rdi), %rax 
.50032: cmpq %rax, 0x70(%rdx) 
.50036: jg .50080 
.50038: jl .50064 
.50040: movq 0x78(%rdi), %r8 
.50044: subl 0x78(%rdx), %r8d 
.50048: jne .50017 
.50050: movq (%rdi), %rsi 
.50053: movq (%rdx), %rdi 
.50056: jmp .29456 
.50061: nopl (%rax) 
.50064: movl $1, %r8d 
.50070: movl %r8d, %eax 
.50073: ret 
.50074: nopw (%rax, %rax) 
.50080: movl $0xffffffff, %r8d 
.50086: jmp .50017 
