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
  ja     .vdso_check_tt_ptr
  lea    .loader_map_end(%rip),%rdx
  cmp    %rax,(%rdx)
  jg     .copy_and_ret_tt_ptr
.vdso_check_tt_ptr:
  lea    .vdso_start(%rip),%rdx
  cmp    %rax,(%rdx)
  ja     .global_look_up_tt_ptr
  lea    .vdso_end(%rip),%rdx
  cmp    %rax,(%rdx)
  jg     .copy_and_ret_tt_ptr
.global_look_up_tt_ptr:
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
.fetch_target_tt_ptr:
  lea    (%r8,%rax,8),%rax
  movslq (%rax),%rdx
  test   %rdx,%rdx
  je     .die_reg_tt_ptr
  movslq 0x4(%rax),%rax
  lea    (%rax,%rax,4),%rax
  mov    (%r9,%rdx,8),%rdx
  cmp    $0,%rdx
  je     .rep_qprobe_tt_ptr
  lea    (%rdx,%rax,8),%rdx
  cmp    (%rdx),%rbx
  je     .jump_to_target_tt_ptr
.rep_qprobe_tt_ptr:
  add    $0x1,%rcx
  cmp    %rsi,%rcx
  je     .die_reg_tt_ptr
.qprobe_tt_ptr:
  mov    %ecx,%eax
  xor    %edx,%edx
  imul   %ecx,%eax
  add    %edi,%eax
  div    %esi
  mov    %rdx,%rax
  jmp    .fetch_target_tt_ptr
  .align 8
.jump_to_target_tt_ptr:
  add    $8,%rdx
  mov    (%rdx),%rax
  mov    0(%rsp),%rdi
  mov    8(%rsp),%rsi
  mov    16(%rsp),%rcx
  mov    24(%rsp),%rdx
  mov    32(%rsp),%rbx
  mov    40(%rsp),%r8
  mov    48(%rsp),%r9
  add    $56,%rsp
  ret
.die_reg_tt_ptr:
  mov    %rbx,%rax
  mov    0(%rsp),%rdi
  mov    8(%rsp),%rsi
  mov    16(%rsp),%rcx
  mov    24(%rsp),%rdx
  mov    32(%rsp),%rbx
  mov    40(%rsp),%r8
  mov    48(%rsp),%r9
  add    $56,%rsp
  ret
.copy_and_ret_tt_ptr:
  mov    24(%rsp),%rdx
  add    $56,%rsp
  ret
