#pragma once

#include <stddef.h>

/* Exact register layout written by intercept_wrapper.S. RCX/R11 are syscall
 * clobbers and are deliberately absent. */
struct runtime_ctx {
  void *patch_desc;
  long rip;
  long r15;
  long r14;
  long r13;
  long r12;
  long r10;
  long r9;
  long r8;
  long rsp;
  long rbp;
  long rdi;
  long rsi;
  long rbx;
  long rdx;
  long rax;
};

static_assert(sizeof(struct runtime_ctx) == 0x80 &&
                  offsetof(struct runtime_ctx, rsp) == 0x48 &&
                  offsetof(struct runtime_ctx, rax) == 0x78,
              "intercept_wrapper.S context layout");
