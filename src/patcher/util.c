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

#include <errno.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#include "patcher.h"
#include "util.h"

int util_mprotect_no_intercept(void *addr, size_t len, int prot) {
  long res = util_syscall_no_intercept(SYS_mprotect, addr, len, prot);
  int err = patcher_syscall_err_code(res);
  if (err != 0) {
    errno = err;
    return -1;
  }
  return 0;
}

void *util_xmmap_anon(size_t size) {
  long res =
      util_syscall_no_intercept(SYS_mmap, NULL, size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, (off_t)0);
  int err = patcher_syscall_err_code(res);
  if (err != 0) {
    errno = err;
    return NULL;
  }
  return (void *)res;
}

void *util_xmremap(void *addr, size_t old, size_t new) {
  long res =
      util_syscall_no_intercept(SYS_mremap, addr, old, new, MREMAP_MAYMOVE);
  int err = patcher_syscall_err_code(res);
  if (err != 0) {
    errno = err;
    return NULL;
  }
  return (void *)res;
}

int util_xmunmap(void *addr, size_t len) {
  long res = util_syscall_no_intercept(SYS_munmap, addr, len);
  int err = patcher_syscall_err_code(res);
  if (err != 0) {
    errno = err;
    return -1;
  }
  return 0;
}

long util_xlseek(long fd, unsigned long off, int whence) {
  long res = util_syscall_no_intercept(SYS_lseek, fd, off, whence);
  int err = patcher_syscall_err_code(res);
  if (err != 0) {
    errno = err;
    return -1;
  }
  return res;
}

int util_xread(long fd, void *buf, size_t size) {
  unsigned char *next = buf;
  while (size != 0) {
    long res = util_syscall_no_intercept(SYS_read, fd, next, size);
    if (res == -EINTR)
      continue;
    int err = patcher_syscall_err_code(res);
    if (err != 0 || res == 0) {
      errno = err != 0 ? err : ENOEXEC;
      return -1;
    }
    next += res;
    size -= (size_t)res;
  }
  return 0;
}
