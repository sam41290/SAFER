.88352: endbr64 
.88356: pushq %rbx 
.88357: movq %rsi, %rbx 
.88360: testq %rsi, %rsi 
.88363: jne .88370 
.88365: testq %rdi, %rdi 
.88368: jne .88400 
.88370: movq %rbx, %rsi 
.88373: callq .19424 
.88378: testq %rax, %rax 
.88381: jne .88388 
.88383: testq %rbx, %rbx 
.88386: jne .88409 
.88388: popq %rbx 
.88389: ret 
.88400: callq .18128 
.88405: xorl %eax, %eax 
.88407: popq %rbx 
.88408: ret 
.88409: hlt 
.88414: nop 
.88416: endbr64 
.88420: movq %rsi, %rax 
.88423: mulq %rdx 
.88426: movq %rax, %rsi 
.88429: seto %al 
.88432: testq %rsi, %rsi 
.88435: js .88447 
.88437: movzbl %al, %eax 
.88440: testq %rax, %rax 
.88443: jne .88447 
.88445: jmp .88352 
.88447: pushq %rax 
.88448: hlt 
