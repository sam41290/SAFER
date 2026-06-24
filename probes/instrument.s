	.file	"instrument.c"
	.text
	.globl	filter
	.data
	.align 32
	.type	filter, @object
	.size	filter, 152
filter:
	.value	32
	.byte	0
	.byte	0
	.long	4
	.value	21
	.byte	1
	.byte	0
	.long	-1073741762
	.value	6
	.byte	0
	.byte	0
	.long	0
	.value	32
	.byte	0
	.byte	0
	.long	0
	.value	21
	.byte	0
	.byte	1
	.long	231
	.value	6
	.byte	0
	.byte	0
	.long	2147418112
	.value	21
	.byte	0
	.byte	1
	.long	12
	.value	6
	.byte	0
	.byte	0
	.long	2147418112
	.value	21
	.byte	0
	.byte	1
	.long	9
	.value	6
	.byte	0
	.byte	0
	.long	2147418112
	.value	21
	.byte	0
	.byte	1
	.long	11
	.value	6
	.byte	0
	.byte	0
	.long	2147418112
	.value	21
	.byte	0
	.byte	1
	.long	1
	.value	6
	.byte	0
	.byte	0
	.long	2147418112
	.value	21
	.byte	0
	.byte	1
	.long	5
	.value	6
	.byte	0
	.byte	0
	.long	2147418112
	.value	21
	.byte	0
	.byte	1
	.long	59
	.value	6
	.byte	0
	.byte	0
	.long	2147418112
	.value	6
	.byte	0
	.byte	0
	.long	0
	.globl	filterprog
	.section	.data.rel.local,"aw"
	.align 16
	.type	filterprog, @object
	.size	filterprog, 16
filterprog:
	.value	19
	.zero	6
	.quad	filter
	.section	.rodata
.LC0:
	.string	"Could not start seccomp:"
	.text
	.globl	install_syscall_filter
	.type	install_syscall_filter, @function
install_syscall_filter:
.LFB6:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$0, %r8d
	movl	$0, %ecx
	movl	$0, %edx
	movl	$1, %esi
	movl	$38, %edi
	movl	$0, %eax
	call	prctl@PLT
	testl	%eax, %eax
	je	.L2
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	call	perror@PLT
	movl	$1, %edi
	call	exit@PLT
.L2:
	leaq	filterprog(%rip), %rax
	movq	%rax, %rdx
	movl	$2, %esi
	movl	$22, %edi
	movl	$0, %eax
	call	prctl@PLT
	cmpl	$-1, %eax
	jne	.L4
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	call	perror@PLT
	movl	$1, %edi
	call	exit@PLT
.L4:
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	install_syscall_filter, .-install_syscall_filter
	.globl	main
	.type	main, @function
main:
.LFB7:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$0, %eax
	call	install_syscall_filter
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE7:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
