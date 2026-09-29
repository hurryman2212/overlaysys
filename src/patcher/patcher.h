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

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("hidden"))) void syscall_clone_child(void);
__attribute__((visibility("hidden"))) void syscall_clone_parent(long child_tid);
/* Zero completes a syscall with its raw result in *ret; nonzero asks the
 * backend to execute it. Per-thread bypass and clone validation belong to
 * the OverlaySys runtime. */
__attribute__((visibility("hidden"))) int syscall_intercept(long num, long a,
                                                            long b, long c,
                                                            long d, long e,
                                                            long f, long *ret);

__attribute__((visibility("hidden"))) long util_syscall_no_intercept(long, ...);
__attribute__((visibility("hidden"))) int
patcher_patch(size_t len, const char *const *paths, bool skip_missing);
__attribute__((visibility("hidden"))) int
patcher_patch_all(size_t len, const char *const *inhibit_patch);
__attribute__((visibility("hidden"))) int patcher_patch_check(const char *path,
                                                              bool *patched);

static inline int patcher_syscall_err_code(long res) {
  return res < 0 && res >= -4095 ? (int)-res : 0;
}

#ifdef __cplusplus
}
#endif
