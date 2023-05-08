.init_shstk:
  subq $56,%rsp
  movq %rax,48(%rsp)
  movq %rdi,40(%rsp)
  movq %rsi,32(%rsp)
  movq %rdx,24(%rsp)
  movq %r10,16(%rsp)
  movq %r8,8(%rsp)
  movq %r9,(%rsp)
  movq $0x9,%rax
  movq $0,%rdi
  movq $0x800000,%rsi
  movq $0x3,%rdx
  movq $0x22,%r10
  movq $-1,%r8
  movq $0,%r9
  syscall
  cmpq $0,%rax
  jle .abort_shstk
  movq %rax,%fs:0x78
  movq (%rsp),%r9
  movq 8(%rsp),%r8
  movq 16(%rsp),%r10
  movq 24(%rsp),%rdx
  movq 32(%rsp),%rsi
  movq 40(%rsp),%rdi
  movq 48(%rsp),%rax
  addq $56,%rsp
  retq

