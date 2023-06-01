  sub    $56,%rsp
  mov    %rdi,0(%rsp)
  mov    %rsi,8(%rsp)
  mov    %rcx,16(%rsp)
  mov    %rdx,24(%rsp)
  mov    %rbx,32(%rsp)
  mov    %r8,40(%rsp)
  mov    %r9,48(%rsp)
  mov .gtt_node(%rip),%rdx
  cmp %rax,16(%rdx)
  jg .loader_check
  cmp %rax,24(%rdx)
  jle .loader_check
  mov   %rax,%rbx
  mov   %rdx,%rax
  mov   56(%rax),%rdx
  mov   64(%rax),%rsi
  mov   72(%rax),%rcx
  mov    48(%rax),%r8
  mov   32(%rax),%r9
  mov   8(%rax),%rdi
  mov   %rbx,%rax
  sub   %rdi,%rax
  jmp   .local_lookup
.loader_check:
  lea    .loader_map_start(%rip),%rdx
  cmp    %rax,(%rdx)
  ja     .vdso_check
  lea    .loader_map_end(%rip),%rdx
  cmp    %rax,(%rdx)
  jg     .copy_and_ret
.vdso_check:
  lea    .vdso_start(%rip),%rdx
  cmp    %rax,(%rdx)
  ja     .global_look_up
  lea    .vdso_end(%rip),%rdx
  cmp    %rax,(%rdx)
  jg     .copy_and_ret
.global_look_up:
  mov    %rax,%rbx
  mov    .hash_tbl_bit_sz(%rip),%rdx
  mov    .hash_tbl_sz(%rip),%rsi
  mov    (%rdx),%rdx
  mov    (%rsi),%rsi
  mov    .hash_key(%rip),%rcx
  shr    $0xc,%rax
  imul   %rcx,%rax
  mov    $0x40,%ecx
  lea    -0x1(%rsi),%rdi
  sub    %edx,%ecx
  shr    %cl,%rax
  and    %rax,%rdi
  xor    %r8,%r8
  mov    .hash_tbl(%rip),%r8
  mov    (%r8),%r8
  mov    $0x0,%rcx
  mov    %rdi,%rax
.fetch_module:
  add    %rax,%rax
  lea    (%r8,%rax,8),%rax
  mov    %rbx,%rdx
  shr    $0xc,%rdx
  cmp    (%rax),%rdx
  jne    .rep_qprobe
  mov   8(%rax),%rax
  mov   56(%rax),%rdx
  mov   64(%rax),%rsi
  mov   72(%rax),%rcx
  xor    %r8,%r8
  mov    48(%rax),%r8
  mov   32(%rax),%r9
  mov   8(%rax),%rdi
  mov   %rbx,%rax
  sub   %rdi,%rax
  jmp   .local_lookup
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
  jmp    .fetch_module
.local_lookup:
  imul   %rcx,%rax
  mov    $0x40,%ecx
  lea    -0x1(%rsi),%rdi
  sub    %edx,%ecx
  shr    %cl,%rax
  and    %rax,%rdi
  mov    $0x0,%rcx
  mov    %rdi,%rax
.fetch_target:
  lea    (%r8,%rax,8),%rax
  mov    (%rax),%rax
  lea    (%rax,%rax,4),%rax
  lea    (%r9,%rax,8),%rdx
  cmp    (%rdx),%rbx
  jne    .rep_qprobe_local
  jmp   .jump_to_target
.rep_qprobe_local:
  add    $0x1,%rcx
  cmp    %rsi,%rcx
  je     .die_reg
.qprobe_local:
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
