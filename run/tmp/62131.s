.19887: hlt 
.62131: nopw %cs:(%rax, %rax) 
.62142: nop 
.62144: endbr64 
.62148: cmpq $0, 0x20(%rdi) 
.62153: je .62208 
.62155: subq $8, %rsp 
.62159: movq (%rdi), %rax 
.62162: movq 8(%rdi), %rdx 
.62166: cmpq %rdx, %rax 
.62169: jb .62185 
.62171: jmp .19887 
.62176: addq $0x10, %rax 
.62180: cmpq %rdx, %rax 
.62183: jae .62215 
.62185: movq (%rax), %r8 
.62188: testq %r8, %r8 
.62191: je .62176 
.62193: movq %r8, %rax 
.62196: addq $8, %rsp 
.62200: ret 
.62208: xorl %r8d, %r8d 
.62211: movq %r8, %rax 
.62214: ret 
.62215: jmp .19887 
