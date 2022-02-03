.atf_function:
.LFB6:
	pushq	%rax
	pushq	%rdx
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$48, %rsp
	movq	%rdi, -40(%rbp)
	movl	%esi, -44(%rbp)
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	movl	$0, -20(%rbp)
	movq	$0, -16(%rbp)
.L5:
	movl	-20(%rbp), %eax
	movslq	%eax, %rdx
	movq	%rdx, %rax
	addq	%rax, %rax
	addq	%rdx, %rax
	salq	$3, %rax
	movq	%rax, %rdx
	movq	-40(%rbp), %rax
	addq	%rdx, %rax
	movq	(%rax), %rax
	testq	%rax, %rax
	jne	.L2
	movl	$0, %edi
    int3
.L2:
	movl	-20(%rbp), %eax
	movslq	%eax, %rdx
	movq	%rdx, %rax
	addq	%rax, %rax
	addq	%rdx, %rax
	salq	$3, %rax
	movq	%rax, %rdx
	movq	-40(%rbp), %rax
	addq	%rdx, %rax
	movq	(%rax), %rdx
	movl	-44(%rbp), %eax
	cltq
	cmpq	%rax, %rdx
	jne	.L5
	movl	-20(%rbp), %eax
	movslq	%eax, %rdx
	movq	%rdx, %rax
	addq	%rax, %rax
	addq	%rdx, %rax
	salq	$3, %rax
	movq	%rax, %rdx
	movq	-40(%rbp), %rax
	addq	%rdx, %rax
	movq	8(%rax), %rax
	movq	%rax, -16(%rbp)
	nop
	leave;
	popq    %rdx
	popq	%rax
    push %rax
    mov %rax,-16(%rsp);
    pop %rax;
    jmp *-24(%rsp);
	nop
	movq	-8(%rbp), %rax
	xorq	%fs:40, %rax
	je	.L6
    int3
.L6:
	leave
	ret
