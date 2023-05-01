  sub    $56,%rsp
  mov    %rdi,0(%rsp)
  mov    %rsi,8(%rsp)
  mov    %rcx,16(%rsp)
  mov    %rdx,24(%rsp)
  mov    %rbx,32(%rsp)
  mov    %r8,40(%rsp)
  mov    %r9,48(%rsp)
  lea    .loader_map_start(%rip),%rdx
  cmp    %rax,(%rdx)
  ja     .global_look_up
  lea    .loader_map_end(%rip),%rdx
  cmp    %rax,(%rdx)
  jg     .copy_and_ret
.global_look_up:
  mov    %rax,%rbx
  mov    .hash_tbl_bit_sz(%rip),%rdx
  mov    .hash_tbl_sz(%rip),%rsi
  mov    (%rdx),%rdx
  mov    (%rsi),%rsi
  mov    .hash_key(%rip),%rcx
  imul   %rcx,%rax
  mov    $0x40,%ecx
  lea    -0x1(%rsi),%rdi
  sub    %edx,%ecx
  shr    %cl,%rax
  and    %rax,%rdi
  xor    %r8,%r8
  mov    .hash_tbl(%rip),%r8
  mov    (%r8),%r8
  mov    .att_arr(%rip),%r9
  mov    $0x0,%rcx
  mov    %rdi,%rax
.fetch_target:
  lea    (%r8,%rax,8),%rax
  movslq (%rax),%rdx
  test   %rdx,%rdx
  je     .die_reg
  movslq 0x4(%rax),%rax
  lea    (%rax,%rax,4),%rax
  mov    (%r9,%rdx,8),%rdx
  lea    (%rdx,%rax,8),%rdx
  cmp    (%rdx),%rbx
  je     .jump_to_target
.rep_qprobe:
  add    $0x1,%rcx
  cmp    %rsi,%rcx
  je     .die_reg
.qprobe:
  mov    %ecx,%eax
  xor    %edx,%edx
  imul   %ecx,%eax
  add    %edi,%eax
  div    %esi
  mov    %rdx,%rax
  jmp    .fetch_target
  .align 8
.jump_to_target:
  add    $8,%rdx
  cmp    (%rdx),%rbx
  je     .jmp_new_addr
  add    $16,%rdx
  mov    %rdx,%rax
  mov    0(%rsp),%rdi
  mov    8(%rsp),%rsi
  mov    16(%rsp),%rcx
  mov    24(%rsp),%rdx
  mov    32(%rsp),%rbx
  mov    40(%rsp),%r8
  mov    48(%rsp),%r9
  add    $56,%rsp
  jmp    *%rax
.die_reg:
  hlt
.jmp_new_addr:
  mov    (%rdx),%rax
  mov    0(%rsp),%rdi
  mov    8(%rsp),%rsi
  mov    16(%rsp),%rcx
  mov    32(%rsp),%rbx
  mov    40(%rsp),%r8
  mov    48(%rsp),%r9
.copy_and_ret:
  mov    %rax,%r11
  mov    24(%rsp),%rdx
  mov    %fs:0x88,%rax
  add    $56,%rsp
  jmp    *%r11
