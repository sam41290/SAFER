.30668: nopl (%rax) 
.30672: endbr64 
.30676: movl .147992(%rip), %eax 
.30682: testl %eax, %eax 
.30684: jne .30701 
.30686: movl .147988(%rip), %eax 
.30692: addl $1, %eax 
.30695: movl %eax, .147988(%rip) 
.30701: ret 
