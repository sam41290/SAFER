#define DECODE \
  mov att_arr(%rip),%rcx \
  mov %rax,%rdx \
  shr $28,%rdx \
  and $0xfff,%rdx \
  mov (%rcx,%rdx,8),%rcx \
  and $0xfffffff,%rax

_gtf_asm_reg_new:
  sub $40,%rsp\n\
  mov %rcx,0(%rsp)\n\
  mov %rdx,8(%rsp)\n\
  mov %rax,%rdx\n\
  shr $44, %rdx\n\
  cmp $0xf,%rdx\n\
  jne .reg_full_att\n\
  mov att_arr(%rip),%rdx\n\
  and $0xfffffffffff,%rax\n\
  mov %rax,%rcx\n\
  shr $4,%eax\n\
  shr $32,%rcx\n\
  add (%rdx,%rcx,8),%rax\n\
  mov 16(%rax),%rax\n\
  mov 0(%rsp),%rcx\n\
  mov 8(%rsp),%rdx\n\
  jmp *%rax\n\
.reg_full_att:\n\
  mov gtt(%rip),%rcx\n\
.reg_gtt_lookup:\n\
  cmp $0,%rcx\n\
  je .reg_copy_and_ret\n\
  cmp %rax,16(%rcx)\n\
  jg .reg_rep\n\
  cmp %rax,24(%rcx)\n\
  jle .reg_rep\n\
  mov 48(%rcx),%rdx\n\
  cmp $0,%rdx\n\
  je .reg_copy_and_ret\n\
  mov %rdi,16(%rsp)\n\
  mov 8(%rcx),%rdi\n\
  sub %rdi,%rax\n\
  mov %rax,-16(%rsp)\n\
  mov %rdi,32(%rsp)\n\
  mov 32(%rcx),%rdi\n\
  mov %rdi,-24(%rsp)\n\
  mov 72(%rcx),%rdi\n\
  imul %rdi,%rax\n\
  mov 64(%rcx),%rdi\n\
  mov 56(%rcx),%rcx\n\
  mov %rcx,-8(%rsp)\n\
  mov $64,%rcx\n\
  sub -8(%rsp),%rcx\n\
  shr %cl,%rax\n\
  sub $1,%rdi\n\
  and %rdi,%rax\n\
  lea (%rdx,%rax,8),%rcx\n\
  mov (%rcx),%rax\n\
  cmp $0,%rax\n\
  je .die_reg\n\
  shl $0x5,%rax\n\
  mov -24(%rsp),%rcx\n\
  add %rcx,%rax\n\
  mov 16(%rax),%rax\n\
.reg_return:\n\
  mov 0(%rsp),%rcx\n\
  mov 8(%rsp),%rdx\n\
  mov 16(%rsp),%rdi\n\
  jmp *%rax\n\
.die_reg:\n\
  mov -16(%rsp),%rdi\n\
  mov 32(%rsp),%rsi\n\
  call die\n\
.reg_rep:\n\
  mov 80(%rcx),%rcx\n\
  jmp .reg_gtt_lookup\n\
.reg_copy_and_ret:\n\
  mov %rax,%r11\n\
  mov 0(%rsp),%rcx\n\
  mov 8(%rsp),%rdx\n\
  mov 24(%rsp),%rax\n\
  add $40,%rsp\n\
  jmp *%r11\n\

_gtf_asm_stack_new:
  sub $40,%rsp\n\
  mov %rcx,0(%rsp)\n\
  mov %rdx,8(%rsp)\n\
  mov %rax,%rdx\n\
  shr $44, %rdx\n\
  cmp $0xf,%rdx\n\
  jne .stack_full_att\n\
  mov att_arr(%rip),%rdx\n\
  and $0xfffffffffff,%rax\n\
  mov %rax,%rcx\n\
  shr $4,%eax\n\
  shr $32,%rcx\n\
  add (%rdx,%rcx,8),%rax\n\
  mov 8(%rax),%rax\n\
.stack_copy_and_ret:\n\
  mov %rax,32(%rsp)\n\
  mov 0(%rsp),%rcx\n\
  mov 8(%rsp),%rdx\n\
  mov 24(%rsp),%rax\n\
  add $32,%rsp\n\
  ret\n\
.stack_full_att:\n\
  mov gtt(%rip),%rcx\n\
.stack_gtt_lookup:\n\
  cmp $0,%rcx\n\
  je .stack_copy_and_ret\n\
  cmp %rax,16(%rcx)\n\
  jg .stack_rep\n\
  cmp %rax,24(%rcx)\n\
  jle .stack_rep\n\
  mov 48(%rcx),%rdx\n\
  cmp $0,%rdx\n\
  je .stack_copy_and_ret\n\
  mov %rdi,16(%rsp)\n\
  mov 8(%rcx),%rdi\n\
  sub %rdi,%rax\n\
  mov %rax,-16(%rsp)\n\
  mov %rdi,32(%rsp)\n\
  mov 32(%rcx),%rdi\n\
  mov %rdi,-24(%rsp)\n\
  mov 72(%rcx),%rdi\n\
  imul %rdi,%rax\n\
  mov 64(%rcx),%rdi\n\
  mov 56(%rcx),%rcx\n\
  mov %rcx,-8(%rsp)\n\
  mov $64,%rcx\n\
  sub -8(%rsp),%rcx\n\
  shr %cl,%rax\n\
  sub $1,%rdi\n\
  and %rdi,%rax\n\
  lea (%rdx,%rax,8),%rcx\n\
  mov (%rcx),%rax\n\
  cmp $0,%rax\n\
  je .die_stack\n\
  shl $0x5,%rax\n\
  mov -24(%rsp),%rcx\n\
  add %rcx,%rax\n\
  mov 8(%rax),%rax\n\
.stack_return:\n\
  mov %rax,32(%rsp)\n\
  mov 0(%rsp),%rcx\n\
  mov 8(%rsp),%rdx\n\
  mov 16(%rsp),%rdi\n\
  mov 24(%rsp),%rax\n\
  add $32,%rsp\n\
  ret\n\
.stack_rep:\n\
  mov 80(%rcx),%rcx\n\
  jmp .stack_gtt_lookup\n\
.die_stack:\n\
  mov -16(%rsp),%rdi\n\
  mov 32(%rsp),%rsi\n\
  call die\n\

 .align 16
.globl _gtf_asm_stack
_gtf_asm_stack_old:
  sub $40,%rsp\n\
  mov %rcx,0(%rsp)\n\
  mov %rdx,8(%rsp)\n\
  mov %rdi,16(%rsp)\n\
  mov %rax,32(%rsp)\n\
  mov %rax,%rdx\n\
  shr $48, %rdx\n\
  cmp $0xf,%rdx\n\
  mov gtt(%rip),%rcx\n\
  jne .stack_full_att\n\
.stack_decode:\n\
  mov att_arr(%rip),%rcx\n\
  mov %rax,%rdx\n\
  shr $28,%rdx\n\
  and $0xfff,%rdx\n\
  mov (%rcx,%rdx,8),%rcx\n\
  and $0xfffffff,%rax\n\
.stack_get_ptr:\n\
  shl $0x5,%rax\n\
  add %rcx,%rax\n\
  mov 8(%rax),%rax\n\
.stack_copy_and_ret:\n\
  mov %rax,32(%rsp)\n\
.stack_return:\n\
  mov 0(%rsp),%rcx\n\
  mov 8(%rsp),%rdx\n\
  mov 16(%rsp),%rdi\n\
  mov 24(%rsp),%rax\n\
  add $32,%rsp\n\
  ret\n\
.stack_full_att:\n\
  cmp $0,%rcx\n\
  je .stack_return\n\
  cmp %rax,16(%rcx)\n\
  jg .stack_rep\n\
  cmp %rax,24(%rcx)\n\
  jle .stack_rep\n\
  mov %rax,32(%rsp)\n\
  mov 8(%rcx),%rdi\n\
  sub %rdi,%rax\n\
  mov %rax,-16(%rsp)\n\
  mov 32(%rcx),%rdi\n\
  mov %rdi,-24(%rsp)\n\
  mov 72(%rcx),%rdi\n\
  imul %rdi,%rax\n\
  mov 48(%rcx),%rdx\n\
  cmp $0,%rdx\n\
  je .stack_return\n\
  mov 16(%rcx),%rdi\n\
  mov %rdi,32(%rsp)\n\
  mov 64(%rcx),%rdi\n\
  mov 56(%rcx),%rcx\n\
  mov %rcx,-8(%rsp)\n\
  mov $64,%rcx\n\
  sub -8(%rsp),%rcx\n\
  shr %cl,%rax\n\
  sub $1,%rdi\n\
  and %rdi,%rax\n\
  lea (%rdx,%rax,8),%rcx\n\
  mov (%rcx),%rax\n\
  cmp $0,%rax\n\
  je .die\n\
  mov -24(%rsp),%rcx\n\
  jmp .stack_get_ptr\n\
.stack_rep:\n\
  mov 80(%rcx),%rcx\n\
  jmp .stack_full_att\n\
.die:\n\
  mov -16(%rsp),%rdi\n\
  mov 32(%rsp),%rsi\n\
  call die\n\


 .align 16
.globl _gtf_asm_reg
_gtf_asm_reg_old:
  sub $40,%rsp\n\
  mov %rcx,0(%rsp)\n\
  mov %rdx,8(%rsp)\n\
  mov %rdi,16(%rsp)\n\
  mov %rax,32(%rsp)\n\
  mov %rax,%rdx\n\
  shr $48, %rdx\n\
  cmp $0xf,%rdx\n\
  mov gtt(%rip),%rcx\n\
  jne .reg_full_att\n\
.reg_decode:\n\
  mov att_arr(%rip),%rcx\n\
  mov %rax,%rdx\n\
  shr $28,%rdx\n\
  and $0xfff,%rdx\n\
  mov (%rcx,%rdx,8),%rcx\n\
  and $0xfffffff,%rax\n\
.reg_get_ptr:\n\
  shl $0x5,%rax\n\
  add %rcx,%rax\n\
  mov 16(%rax),%rax\n\
.reg_return:\n\
  mov 0(%rsp),%rcx\n\
  mov 8(%rsp),%rdx\n\
  mov 16(%rsp),%rdi\n\
  jmp *%rax\n\
.reg_full_att:\n\
  cmp $0,%rcx\n\
  je .reg_copy_and_ret\n\
  cmp %rax,16(%rcx)\n\
  jg .reg_rep\n\
  cmp %rax,24(%rcx)\n\
  jle .reg_rep\n\
  mov %rax,32(%rsp)\n\
  mov 8(%rcx),%rdi\n\
  sub %rdi,%rax\n\
  mov %rax,-16(%rsp)\n\
  mov 32(%rcx),%rdi\n\
  mov %rdi,-24(%rsp)\n\
  mov 72(%rcx),%rdi\n\
  imul %rdi,%rax\n\
  mov 48(%rcx),%rdx\n\
  cmp $0,%rdx\n\
  je .reg_copy_and_ret\n\
  mov 16(%rcx),%rdi\n\
  mov %rdi,32(%rsp)\n\
  mov 64(%rcx),%rdi\n\
  mov 56(%rcx),%rcx\n\
  mov %rcx,-8(%rsp)\n\
  mov $64,%rcx\n\
  sub -8(%rsp),%rcx\n\
  shr %cl,%rax\n\
  sub $1,%rdi\n\
  and %rdi,%rax\n\
  lea (%rdx,%rax,8),%rcx\n\
  mov (%rcx),%rax\n\
  cmp $0,%rax\n\
  je .die_reg\n\
  mov -24(%rsp),%rcx\n\
  jmp .reg_get_ptr\n\
.reg_rep:\n\
  mov 80(%rcx),%rcx\n\
  jmp .reg_full_att\n\
.die_reg:\n\
  mov -16(%rsp),%rdi\n\
  mov 32(%rsp),%rsi\n\
  call die\n\
.reg_copy_and_ret:\n\
  mov 32(%rsp),%r11\n\
  mov 0(%rsp),%rcx\n\
  mov 8(%rsp),%rdx\n\
  mov 16(%rsp),%rdi\n\
  mov 24(%rsp),%rax\n\
  add $40,%rsp\n\
  jmp *%r11\n\



 .align 16
.globl _gtf_asm_linear
_gtf_asm_linear:
  sub $32,%rsp
  mov %rcx,0(%rsp)
  mov %rdx,8(%rsp)
  pushf
  mov %rax,32(%rsp)
  mov %rax,%rdx
  shr $48, %rdx
  cmp $0xf,%rdx
  mov gtt(%rip),%rcx
  jne .linear_full_att
.linear_decode:
  mov att_arr(%rip),%rcx
  mov %rax,%rdx
  shr $28,%rdx
  and $0xfff,%rdx
  mov (%rcx,%rdx,8),%rcx
  and $0xfffffff,%rax
  mov %rax,%rdx
  add %rdx,%rdx
  add %rdx,%rax
  lea (%rcx,%rax,8),%rcx
  add $8,%rcx
  mov (%rcx),%rax
.linear_copy_and_return:
  mov %rax,32(%rsp)
.linear_return:
  popf
  mov 0(%rsp),%rcx
  mov 8(%rsp),%rdx
  mov 16(%rsp),%rax
  add $24,%rsp
  ret
.linear_full_att:
  cmp $0,%rcx
  je .linear_return
  cmp %rax,16(%rcx)
  jg .linear_rep
  cmp %rax,24(%rcx)
  jle .linear_rep
  mov 32(%rcx),%rdx
  cmp $0,%rdx
  je .linear_copy_and_return
  mov 40(%rcx),%rcx
  add $24,%rdx
  sub $24,%rcx
.att_lookup:
  cmp (%rdx),%rax
  je .att_ret
  add $24,%rdx
  cmp %rdx,%rcx
  jle .linear_return
  jmp .att_lookup
.att_ret:
  add $8,%rdx
  mov (%rdx),%rax
  mov %rax,32(%rsp)
  jmp .linear_return
.linear_rep:
  mov 80(%rcx),%rcx
  jmp .linear_full_att
