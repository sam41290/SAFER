.init_shstk:
  pushq %rbp
  pushq %rax
  pushq %rdi
  pushq %rsi
  pushq %rdx
  pushq %r10
  pushq %r8
  pushq %r9
  movq $0x9,%rax
  movq $0,%rdi
  movq $0x1000,%rsi
  movq $0x3,%rdx
  movq $0x22,%r10
  movq $-1,%r8
  movq $0,%r9
  syscall
  cmpq $0,%rax
  jle .abort_shstk
  movq %rax,%fs:0x78
  popq %r9
  popq %r8
  popq %r10
  popq %rdx
  popq %rsi
  popq %rdi
  popq %rax
  popq %rbp
  retq

