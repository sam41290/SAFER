.55208: nopl (%rax, %rax) 
.55216: endbr64 
.55220: pushq %r15 
.55222: movq %rsi, %r15 
.55225: pushq %r14 
.55227: movq %r8, %r14 
.55230: pushq %r13 
.55232: movq %rdi, %r13 
.55235: movq %r15, %rdi 
.55238: pushq %r12 
.55240: movq %rcx, %r12 
.55243: movq %r8, %rcx 
.55246: pushq %rbp 
.55247: movq %rdx, %rbp 
.55250: movq %r12, %rdx 
.55253: pushq %rbx 
.55254: movq %rbp, %rsi 
.55257: movq %r9, %rbx 
.55260: subq $8, %rsp 
.55264: callq .54496 
.55269: testq %rax, %rax 
.55272: js .55296 
.55274: addq $8, %rsp 
.55278: popq %rbx 
.55279: popq %rbp 
.55280: popq %r12 
.55282: popq %r13 
.55284: popq %r14 
.55286: popq %r15 
.55288: ret 
.55296: movq %rax, %rdx 
.55299: movq %r15, %rsi 
.55302: movq %r13, %rdi 
.55305: callq .54768 
.55310: movq %r14, %rdx 
.55313: movq %r12, %rsi 
.55316: movq %rbp, %rdi 
.55319: callq .54912 
.55324: callq *%rbx 
.55326: movq $-1, %rax 
.55333: jmp .55274 
