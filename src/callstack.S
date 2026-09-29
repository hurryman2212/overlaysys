/* Capture the API caller without a libc unwinder or per-syscall bookkeeping.
 * The 17 slots follow the x86-64 DWARF register numbering. */
.text
.global overlaysys_callstack_check
.type overlaysys_callstack_check, @function
.hidden callstack_check
overlaysys_callstack_check:
	.cfi_startproc
	subq $136, %rsp
	.cfi_def_cfa_offset 144
	movq %rax, 0(%rsp)
	movq %rdx, 8(%rsp)
	movq %rcx, 16(%rsp)
	movq %rbx, 24(%rsp)
	movq %rsi, 32(%rsp)
	movq %rdi, 40(%rsp)
	movq %rbp, 48(%rsp)
	leaq 144(%rsp), %rax
	movq %rax, 56(%rsp)
	movq %r8, 64(%rsp)
	movq %r9, 72(%rsp)
	movq %r10, 80(%rsp)
	movq %r11, 88(%rsp)
	movq %r12, 96(%rsp)
	movq %r13, 104(%rsp)
	movq %r14, 112(%rsp)
	movq %r15, 120(%rsp)
	movq 136(%rsp), %rax
	movq %rax, 128(%rsp)
	movq %rsp, %rdx
	call callstack_check
	addq $136, %rsp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.size overlaysys_callstack_check, .-overlaysys_callstack_check
.section .note.GNU-stack,"",@progbits
