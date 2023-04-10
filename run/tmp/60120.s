.60120: nopl (%rax, %rax) 
.60128: endbr64 
.60132: pushq %rbx 
.60133: movq %rdi, %rsi 
.60136: movq %rdi, %rbx 
.60139: xorl %edi, %edi 
.60141: subq $0x20, %rsp 
.60145: movq %fs:0x28, %rax 
.60154: movq %rax, 0x18(%rsp) 
.60159: xorl %eax, %eax 
.60161: callq .18480 
.60166: testl %eax, %eax 
.60168: je .60200 
.60170: movq %rsp, %rdi 
.60173: xorl %esi, %esi 
.60175: callq .18848 
.60180: movq (%rsp), %rax 
.60184: movq %rax, (%rbx) 
.60187: imulq $0x3e8, 8(%rsp), %rax 
.60196: movq %rax, 8(%rbx) 
.60200: movq 0x18(%rsp), %rax 
.60205: xorq %fs:0x28, %rax 
.60214: jne .60222 
.60216: addq $0x20, %rsp 
.60220: popq %rbx 
.60221: ret 
.60222: hlt 
