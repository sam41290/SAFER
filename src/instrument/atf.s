
  sub $40,%rsp
  mov %rcx,0(%rsp)
  mov %rdx,8(%rsp)
  mov .gtt_node(%rip),%rcx
  cmp %rax,16(%rcx)
  jg .reg_full_att
  cmp %rax,24(%rcx)
  jg .reg_att_lookup
.reg_full_att:
  mov .gtt(%rip),%rcx
.reg_gtt_lookup:
  cmp $0,%rcx
  je .reg_copy_and_ret
  cmp %rax,16(%rcx)
  jg .reg_rep
  cmp %rax,24(%rcx)
  jle .reg_rep
.reg_att_lookup:
  mov 48(%rcx),%rdx
  cmp $0,%rdx
  je .reg_copy_and_ret
  mov %rdi,16(%rsp)
  mov 8(%rcx),%rdi
  sub %rdi,%rax
  mov 32(%rcx),%rdi
  mov %rdi,-24(%rsp)
  mov 72(%rcx),%rdi
  imul %rdi,%rax
  mov 64(%rcx),%rdi
  mov 56(%rcx),%rcx
  mov %rcx,-8(%rsp)
  mov $64,%rcx
  sub -8(%rsp),%rcx
  shr %cl,%rax
  sub $1,%rdi
  and %rdi,%rax
  lea (%rdx,%rax,8),%rcx
  mov (%rcx),%rax
  cmp $0,%rax
  je .die_reg
  mov -24(%rsp),%rcx
  lea 0x0(%rax,%rax,4),%rax
  lea 24(%rcx,%rax,8),%rax
.reg_return:
  mov 0(%rsp),%rcx
  mov 8(%rsp),%rdx
  mov 16(%rsp),%rdi
  add $40,%rsp
  jmp *%rax
.die_reg:
  hlt
.reg_rep:
  mov 80(%rcx),%rcx
  jmp .reg_gtt_lookup
.reg_copy_and_ret:
  mov %rax,%r11
  mov 0(%rsp),%rcx
  mov 8(%rsp),%rdx
  add $40,%rsp
  mov %fs:0x88,%rax
  jmp *%r11
