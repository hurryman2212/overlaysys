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

#include <stddef.h>

#include <sys/syscall.h>

#include "../patcher.h"

#include "runtime.h"

struct runtime_wrapper_ret {
  long rax;
  long rdx;
};

/*
 * Route the saved x86 context through OverlaySys before choosing a native
 * execution path. The assembly wrapper interprets rdx as 0: execute on the
 * original stack, 1: return rax, or 2: clone and run post-call setup.
 */
struct runtime_wrapper_ret runtime_intercept(struct runtime_ctx *ctx) {
  long res;
  int nr = (int)ctx->rax; /* Linux ignores the syscall number's upper bits. */

  /* A handled result wins even for syscalls that would change the stack. */
  if (!syscall_intercept(nr, ctx->rdi, ctx->rsi, ctx->rdx, ctx->r10, ctx->r8,
                         ctx->r9, &res))
    return (struct runtime_wrapper_ret){.rax = res, .rdx = 1};

  switch (nr) {
  case SYS_vfork:
  case SYS_rt_sigreturn:
    return (struct runtime_wrapper_ret){.rax = ctx->rax, .rdx = 0};

  case SYS_clone:
#ifdef SYS_clone3
  case SYS_clone3:
#endif
    /* Both new-stack and copied-stack children need OverlaySys state setup;
     * failures need parent cleanup too. Runtime validation safely reads user
     * clone3 arguments, so the machine backend must not dereference them. */
    return (struct runtime_wrapper_ret){.rax = ctx->rax, .rdx = 2};

  default:
    res = util_syscall_no_intercept(nr, ctx->rdi, ctx->rsi, ctx->rdx, ctx->r10,
                                    ctx->r8, ctx->r9);
    return (struct runtime_wrapper_ret){.rax = res, .rdx = 1};
  }
}

/*
 * The assembly path calls back in both children and parents, including native
 * failures, after restoring the stack appropriate to that return path.
 */
struct runtime_wrapper_ret runtime_post_clone(struct runtime_ctx *ctx) {
  if (ctx->rax == 0)
    syscall_clone_child();
  else
    syscall_clone_parent(ctx->rax);

  return (struct runtime_wrapper_ret){.rax = ctx->rax, .rdx = 1};
}
