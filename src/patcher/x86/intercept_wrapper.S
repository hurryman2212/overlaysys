/*
 * Copyright 2016-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <asm/unistd_64.h>

/* Save the machine context around C code reached from a syscall instruction.
 * The fixed frame matches struct ctx; FP/SIMD storage is separately aligned
 * and sized at initialization for the enabled x87/SSE/AVX/AVX-512 components. */

.global intercept_wrapper
.hidden intercept_wrapper
.type intercept_wrapper, @function
.global runtime_intercept
.hidden runtime_intercept
.global runtime_post_clone
.hidden runtime_post_clone
.global patcher_intercept_xstate_mask
.hidden patcher_intercept_xstate_mask
.global patcher_intercept_xstate_size
.hidden patcher_intercept_xstate_size
.global patcher_intercept_xstate_compact
.hidden patcher_intercept_xstate_compact
.global patcher_intercept_xstate_tier
.hidden patcher_intercept_xstate_tier
.global patcher_intercept_xstate_inuse
.hidden patcher_intercept_xstate_inuse
.global patcher_intercept_x87_used
.hidden patcher_intercept_x87_used
.hidden syscall_user_cb_active
.hidden syscall_internal_emulation
.hidden sig_pedantic

.section .rodata
.balign 8
/* Only unconditional native cases in emulate_syscall(). Reads, signal/FD
 * bookkeeping, waits and lifecycle operations must keep their C path. */
.Lnested_native:
	.quad (1 << __NR_write) | (1 << __NR_writev) | (1 << __NR_getpid) | (1 << __NR_sendto) | (1 << __NR_recvfrom) | (1 << __NR_sendmsg) | (1 << __NR_recvmsg)
	.quad 0
	.quad (1 << (__NR_gettid - 128))
	.quad (1 << (__NR_futex - 192))
	.quad (1 << (__NR_recvmmsg - 256)) | (1 << (__NR_sendmmsg - 256))
.Lnested_native_end:

.text

/* Fixed frame:
 * 0x00..0x80: struct ctx
 * 0x88: return address to the generated wrapper
 * 0x90: original rsp, 0x98: patch_desc (generated-wrapper locals)
 * rcx selects the ordinary entry (0) or post-clone entry (1).
 */
intercept_wrapper:
	.cfi_startproc
	/* Nested callbacks already suppress user hooks and epilogues. Native
	 * operations can keep their original stack and registers without any C
	 * processing. Post-clone entries must always run their bookkeeping. */
	testq       %rcx, %rcx
	jnz         .Lsave_ctx
	movq        syscall_user_cb_active@gottpoff(%rip), %r11
	cmpb        $0, %fs:(%r11)
	jne         .Lcheck_native
	movq        syscall_internal_emulation@gottpoff(%rip), %r11
	cmpb        $0, %fs:(%r11)
	je          .Lsave_ctx
.Lcheck_native:
	cmpl        $(.Lnested_native_end-.Lnested_native)*8, %eax
	jae         .Lsave_ctx
	movl        %eax, %ecx
	leaq        .Lnested_native(%rip), %r11
	btq         %rcx, (%r11)
	movl        $0, %ecx /* Keep the ordinary-entry selector and BT carry. */
	jnc         .Lsave_ctx
	xorl        %r11d, %r11d /* Generated wrapper executes the original syscall. */
	retq
.Lsave_ctx:
	subq        $0x88, %rsp
	.cfi_def_cfa_offset 0x90

	movq        %rax, 0x78(%rsp)
	movq        %rdx, 0x70(%rsp)
	movq        %rbx, 0x68(%rsp)
	.cfi_offset 3, -0x28
	movq        %rsi, 0x60(%rsp)
	movq        %rdi, 0x58(%rsp)
	movq        %rbp, 0x50(%rsp)
	.cfi_offset 6, -0x40
	movq        0x90(%rsp), %r11
	movq        %r11, 0x48(%rsp)
	movq        %r8, 0x40(%rsp)
	movq        %r9, 0x38(%rsp)
	movq        %r10, 0x30(%rsp)
	movq        %r12, 0x28(%rsp)
	.cfi_offset 12, -0x68
	movq        %r13, 0x20(%rsp)
	.cfi_offset 13, -0x70
	movq        %r14, 0x18(%rsp)
	.cfi_offset 14, -0x78
	movq        %r15, 0x10(%rsp)
	.cfi_offset 15, -0x80
	movq        0x98(%rsp), %r11
	movq        %r11, (%rsp)
	movq        (%r11), %r11
	movq        %r11, 0x8(%rsp)

	/* rbx anchors the fixed frame while rsp owns aligned FP/SIMD storage. */
	movq        %rsp, %rbx
	.cfi_def_cfa_register %rbx
	subq        patcher_intercept_xstate_size(%rip), %rsp
	andq        $-64, %rsp
	/* Keep the entry kind across XGETBV and remember whether x87 was initial. */
	movq        %rcx, %r14
	xorl        %r15d, %r15d
	cmpl        $0, patcher_intercept_xstate_tier(%rip)
	je          5f
	cmpl        $1, patcher_intercept_xstate_tier(%rip)
	je          7f
	/* Strict mode also retains raw x87 opcode history in initial states. */
	cmpb        $0, sig_pedantic(%rip)
	jne         7f
	cmpb        $0, patcher_intercept_xstate_inuse(%rip)
	je          7f
	/* After observing x87/MMX use, this thread keeps the ordinary save path. */
	movq        patcher_intercept_x87_used@gottpoff(%rip), %r15
	cmpb        $0, %fs:(%r15)
	jne         10f
	/* XINUSE[0] == 0 guarantees the entire x87 component is initial,
	 * including its control, status, tags, pointers and all physical ST data. */
	movl        $1, %ecx
	xgetbv
	testb       $1, %al
	jnz         11f
	movl        $1, %r15d
	stmxcsr     0x18(%rsp)
	jmp         8f
11:	movb        $1, %fs:(%r15)
10:	xorl        %r15d, %r15d
7:	fxsave64    (%rsp)
8:
	cmpl        $1, patcher_intercept_xstate_tier(%rip)
	je          1f
	cmpl        $2, patcher_intercept_xstate_tier(%rip)
	jne         6f
	.irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	vmovups     %ymm\reg, 0x240+32*\reg(%rsp)
	.endr
	jmp         1f
6:
	.irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	vmovups     %zmm\reg, 0x240+64*\reg(%rsp)
	.endr
	.irp reg,0,1,2,3,4,5,6,7
	kmovq       %k\reg, 0xa40+8*\reg(%rsp)
	.endr
	jmp         1f
5:	movl        patcher_intercept_xstate_mask(%rip), %eax
	/* XRSTOR requires zero reserved header bits, including XCOMP_BV. XSAVE
	 * updates requested XSTATE_BV bits only, so initialize the entire header. */
	xorl        %edx, %edx
	movq        %rdx, 0x200(%rsp)
	movq        %rdx, 0x208(%rsp)
	movq        %rdx, 0x210(%rsp)
	movq        %rdx, 0x218(%rsp)
	movq        %rdx, 0x220(%rsp)
	movq        %rdx, 0x228(%rsp)
	movq        %rdx, 0x230(%rsp)
	movq        %rdx, 0x238(%rsp)
	cmpb        $0, patcher_intercept_xstate_compact(%rip)
	je          2f
	/* Unlike XSAVEOPT, XSAVEC safely omits initial state in a fresh buffer. */
	xsavec64    (%rsp)
	jmp         1f
2:
	xsave64     (%rsp)
	jmp         1f
1:	testl       %r15d, %r15d
	jnz         3f
	/* C needs an empty x87 stack without deferred exceptions. XSAVEC can
	 * omit initial x87 data; preserve rounding when cleaning saved state. */
	cmpl        $0, patcher_intercept_xstate_tier(%rip)
	jne         2f
	testb       $1, 0x200(%rsp)
	jz          3f
2:	cmpb        $0, 0x4(%rsp)
	jne         4f
	testb       $0x80, 0x2(%rsp) /* deferred unmasked x87 exception */
	je          3f
4:
	fninit
	fldcw       (%rsp)
3:	movq        %rbx, %rdi
	cmpq        $1, %r14
	je          0f
	call        runtime_intercept
.global callstack_intercept_return
.hidden callstack_intercept_return
callstack_intercept_return:
	jmp         1f
0:	call        runtime_post_clone
1:	/* XSAVE/XRSTOR use eax/edx; retain the two C return values in saved GPRs. */
	movq        %rax, %r12
	movq        %rdx, %r13
	cmpl        $0, patcher_intercept_xstate_tier(%rip)
	je          5f
	testl       %r15d, %r15d
	jz          7f
	movl        $1, %ecx
	xgetbv
	testb       $1, %al
	jz          8f
	/* The hook used x87: restore the initial component once, then use
	 * FXSAVE on subsequent entries. Reserve the XSAVE header before vectors. */
	movq        patcher_intercept_x87_used@gottpoff(%rip), %rax
	movb        $1, %fs:(%rax)
	xorl        %edx, %edx
	movq        %rdx, 0x200(%rsp)
	movq        %rdx, 0x208(%rsp)
	movq        %rdx, 0x210(%rsp)
	movq        %rdx, 0x218(%rsp)
	movq        %rdx, 0x220(%rsp)
	movq        %rdx, 0x228(%rsp)
	movq        %rdx, 0x230(%rsp)
	movq        %rdx, 0x238(%rsp)
	movl        $1, %eax
	xrstor64    (%rsp)
8:	ldmxcsr     0x18(%rsp)
	jmp         9f
7:	fxrstor64   (%rsp)
9:
	cmpl        $1, patcher_intercept_xstate_tier(%rip)
	je          1f
	cmpl        $2, patcher_intercept_xstate_tier(%rip)
	jne         6f
	.irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	vmovups     0x240+32*\reg(%rsp), %ymm\reg
	.endr
	jmp         1f
6:
	.irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	vmovups     0x240+64*\reg(%rsp), %zmm\reg
	.endr
	.irp reg,0,1,2,3,4,5,6,7
	kmovq       0xa40+8*\reg(%rsp), %k\reg
	.endr
	jmp         1f
5:	movl        patcher_intercept_xstate_mask(%rip), %eax
	xorl        %edx, %edx
	xrstor64    (%rsp)
1:	movq        %r12, %rax
	movq        %r13, %r11
	movq        %rbx, %rsp
	.cfi_def_cfa_register %rsp

	movq        0x70(%rsp), %rdx
	movq        0x68(%rsp), %rbx
	.cfi_restore 3
	movq        0x60(%rsp), %rsi
	movq        0x58(%rsp), %rdi
	movq        0x50(%rsp), %rbp
	.cfi_restore 6
	movq        0x40(%rsp), %r8
	movq        0x38(%rsp), %r9
	movq        0x30(%rsp), %r10
	movq        0x28(%rsp), %r12
	.cfi_restore 12
	movq        0x20(%rsp), %r13
	.cfi_restore 13
	movq        0x18(%rsp), %r14
	.cfi_restore 14
	movq        0x10(%rsp), %r15
	.cfi_restore 15
	addq        $0x88, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
.size intercept_wrapper, .-intercept_wrapper

.section .note.GNU-stack,"",@progbits
