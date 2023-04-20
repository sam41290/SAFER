  sub    $48,%rsp
  mov    %rdi,0(%rsp)
  mov    %rsi,8(%rsp)
  mov    %rcx,16(%rsp)
  mov    %rdx,24(%rsp)
  mov    %rbx,32(%rsp)
  mov    %r8,40(%rsp)
  mov    %rax,%rbx
  movslq .hash_tbl_bit_sz(%rip),%rdx
  movslq .hash_tbl_sz(%rip),%rsi
  movslq (%rdx),%rdx
  movslq (%rsi),%rsi
  movabs $0x9e3779b97f4a7c55,%rcx
  imul   %rcx,%rax
  mov    $0x40,%ecx
  lea    -0x1(%rsi),%rdi
  sub    %edx,%ecx
  shr    %cl,%rdi
  and    %rax,%rdi
  movslq .hash_tbl(%rip),%r8
  mov    (%r8),%r8
  mov    %rdi,%rcx
  lea    (%rdi,%rdi,2),%rdi
  mov    (%r8,%rdi,8),%rdx
  test   %rdx,%rdx
  je     .die_reg
  mov    %ecx,%edi
  cmp    %rbx,%rdx
  je     .jump_to_target
  cmp    $0x1,%esi
  jle    .die_reg
  mov    $0x1,%ecx
  jmp    .qprobe
.rep_qprobe:
  test   %rax,%rax
  je     .die_reg
  add    $0x1,%ecx
  cmp    %esi,%ecx
  je     .die_reg
.qprobe:
  mov    %ecx,%eax
  xor    %edx,%edx
  imul   %ecx,%eax
  add    %edi,%eax
  div    %esi
  mov    %edx,%eax
  lea    (%rax,%rax,2),%rax
  mov    (%r8,%rax,8),%rax
  cmp    %rbx,%rax
  jne    .rep_qprobe
  mov    %rdx,%rdi
.jump_to_target:
  lea    (%rdi,%rdi,2),%rdi
  lea    (%r8,%rdi,8),%rdx
  add    $8,%rdx
  mov    (%rdx),%rax
  mov    %rdi,0(%rsp)
  mov    %rsi,8(%rsp)
  mov    %rcx,16(%rsp)
  mov    %rdx,24(%rsp)
  mov    %rbx,32(%rsp)
  mov    %r8,40(%rsp)
  add    $48,%rsp
  jmp    *%rax
.die_reg:
  hlt


