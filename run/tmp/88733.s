.88733: nopl (%rax) 
.88736: endbr64 
.88740: movq %rdi, %rax 
.88743: subq $8, %rsp 
.88747: mulq %rsi 
.88750: seto %dl 
.88753: testq %rax, %rax 
.88756: js .88781 
.88758: movzbl %dl, %edx 
.88761: testq %rdx, %rdx 
.88764: jne .88781 
.88766: callq .19040 
.88771: testq %rax, %rax 
.88774: je .88781 
.88776: addq $8, %rsp 
.88780: ret 
.88781: hlt 
