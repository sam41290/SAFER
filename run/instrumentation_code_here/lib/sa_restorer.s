.text
.globl  sa_restorer
.type   sa_restorer, @function
sa_restorer:
movq $0xf,%rax
syscall
