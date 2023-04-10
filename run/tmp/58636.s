.58636: nopl (%rax) 
.58640: endbr64 
.58644: subq $8, %rsp 
.58648: callq .58672 
.58653: testq %rax, %rax 
.58656: je .58663 
.58658: addq $8, %rsp 
.58662: ret 
.58663: hlt 
