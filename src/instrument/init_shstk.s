.init_shstk:
  pushq %rbp
  movq %rsp,%rbp
  movq $0x9,%rax
  xor %rdi,%rdi
  movq $0x4000,%rsi
  movq $0x3,%rdx
  movq $0x22,%rcx
  movq $-1,%r8
  movq $0x0,%r9
  syscall
  cmpq $-1,%rax
  je abort_shstk
  movq %rax,%fs:0x78  
  movq %rbp,%rsp
  popq %rbp
  retq

.abort_shstk:
  mov $60,%rax
  mov $1,%rdi
  syscall


