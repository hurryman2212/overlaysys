/*
 * Copyright 2016-2020, Intel Corporation
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

/*
 * disasm_wrapper.c -- connecting the interceptor code
 * to the disassembler code from the capstone project.
 *
 * See:
 * http://www.capstone-engine.org/lang_c.html
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <capstone/capstone.h>

#include "../util.h"

#include "disasm_wrapper.h"

struct disasm_wrapper_ctx {
  csh handle;
  cs_insn *inst;
  const unsigned char *begin;
  const unsigned char *end;
};

static int disasm_wrapper_capstone_errno(cs_err err) {
  switch (err) {
  case CS_ERR_MEM:
    return ENOMEM;
  case CS_ERR_ARCH:
  case CS_ERR_MODE:
  case CS_ERR_DETAIL:
  case CS_ERR_VERSION:
  case CS_ERR_DIET:
  case CS_ERR_SKIPDATA:
  case CS_ERR_X86_ATT:
  case CS_ERR_X86_INTEL:
  case CS_ERR_X86_MASM:
    return EOPNOTSUPP;
  case CS_ERR_HANDLE:
  case CS_ERR_CSH:
  case CS_ERR_OPTION:
    return EINVAL;
  default:
    return EIO;
  }
}

/*
 * disasm_wrapper_init -- should be called before disassembling a region of
 * code. The context created contains the context capstone needs ( or generally
 * the underlying disassembling library, if something other than capstone might
 * be used ).
 *
 * Any allocated context is returned to the caller even on failure and must
 * eventually be passed to disasm_wrapper_destroy.
 */
int disasm_wrapper_init(const unsigned char *begin, const unsigned char *end,
                        struct disasm_wrapper_ctx **out) {
  struct disasm_wrapper_ctx *ctx;
  cs_err err;

  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }
  *out = NULL;
  if (begin == NULL || (uintptr_t)end < (uintptr_t)begin) {
    errno = EINVAL;
    return -1;
  }

  ctx = util_xmmap_anon(sizeof(*ctx));
  if (ctx == NULL)
    return -1;
  *out = ctx;
  ctx->begin = begin;
  ctx->end = end;

  /*
   * Initialize the disassembler.
   * The handle here must be passed to capstone each time it is used.
   */
  err = cs_open(CS_ARCH_X86, CS_MODE_64, &ctx->handle);
  if (err != CS_ERR_OK)
    goto fail;

  /*
   * Kindly ask capstone to return some details about the instruction.
   * Without this, it only prints the instruction, and we would need
   * to parse the resulting string.
   */
  err = cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
  if (err != CS_ERR_OK)
    goto fail;

  if ((ctx->inst = cs_malloc(ctx->handle)) == NULL) {
    err = cs_errno(ctx->handle);
    if (err == CS_ERR_OK)
      err = CS_ERR_MEM;
    goto fail;
  }

  return 0;

fail:
  errno = disasm_wrapper_capstone_errno(err);
  return -1;
}

/*
 * disasm_wrapper_destroy -- see comments for above routine
 */
int disasm_wrapper_destroy(struct disasm_wrapper_ctx *ctx) {
  if (ctx == NULL)
    return 0;

  if (ctx->inst != NULL) {
    cs_free(ctx->inst, 1);
    ctx->inst = NULL;
  }
  if (ctx->handle != 0) {
    cs_err err = cs_close(&ctx->handle);
    if (err != CS_ERR_OK) {
      errno = disasm_wrapper_capstone_errno(err);
      return -1;
    }
  }
  return util_xmunmap(ctx, sizeof(*ctx));
}

/*
 * check_op - checks a single operand of an instruction, looking
 * for RIP relative addressing.
 */
static int disasm_wrapper_check_op(struct intercept_disasm_res *res,
                                   cs_x86_op *op, const unsigned char *code) {
  /*
   * the address the RIP register is going to contain during the
   * execution of this instruction
   */
  const unsigned char *rip = code + res->len;

  if (op->type == X86_OP_REG) {
    if (op->reg == X86_REG_IP || op->reg == X86_REG_EIP ||
        op->reg == X86_REG_RIP) {
      /*
       * Example: mov %rip, %rax
       */
      res->has_ip_relative_opr = true;
      res->rip_ref_addr = (const unsigned char *)(op->reg == X86_REG_EIP
                                                      ? (uint32_t)(uintptr_t)rip
                                                  : op->reg == X86_REG_IP
                                                      ? (uint16_t)(uintptr_t)rip
                                                      : (uintptr_t)rip);
    }
    if (res->is_jump) {
      /*
       * Example: jmp *(%rax)
       */
      /*
       * An indirect jump can't have arguments other
       * than a register. Reject inconsistent decoder output.
       */
      if (res->is_rel_jump) {
        errno = EIO;
        return -1;
      }
      res->is_indirect_jump = true;
    }
  } else if (op->type == X86_OP_MEM) {
    if (op->mem.base == X86_REG_IP || op->mem.base == X86_REG_EIP ||
        op->mem.base == X86_REG_RIP || op->mem.index == X86_REG_IP ||
        op->mem.index == X86_REG_EIP || op->mem.index == X86_REG_RIP ||
        res->is_jump) {
      res->has_ip_relative_opr = true;
      if (res->is_indirect_jump) {
        errno = EIO;
        return -1;
      }

      if (res->is_jump)
        res->is_rel_jump = true;

      if (op->mem.disp > INT32_MAX || op->mem.disp < INT32_MIN) {
        errno = EOPNOTSUPP;
        return -1;
      }

      uintptr_t ref = (uintptr_t)rip + (int32_t)op->mem.disp;
      if (op->mem.base == X86_REG_EIP || op->mem.index == X86_REG_EIP)
        ref = (uint32_t)ref;
      else if (op->mem.base == X86_REG_IP || op->mem.index == X86_REG_IP)
        ref = (uint16_t)ref;
      res->rip_ref_addr = (const unsigned char *)ref;
    }
  } else if (op->type == X86_OP_IMM) {
    if (res->is_jump) {
      if (res->is_indirect_jump) {
        errno = EIO;
        return -1;
      }
      res->has_ip_relative_opr = true;
      res->is_rel_jump = true;
      res->rip_ref_addr = (void *)op->imm;
    }
  }
  return 0;
}

/*
 * disasm_wrapper_next_inst - Examines a single instruction
 * in a text section. This is only a wrapper around capstone specific code,
 * collecting data that can be used later to make decisions about patching.
 */
int disasm_wrapper_next_inst(struct disasm_wrapper_ctx *ctx,
                             const unsigned char *code,
                             struct intercept_disasm_res *out) {
  static const unsigned char endbr64[] = {0xf3, 0x0f, 0x1e, 0xfa};

  struct intercept_disasm_res res = {.addr = code};
  if (ctx == NULL || out == NULL || ctx->handle == 0 || ctx->inst == NULL ||
      (uintptr_t)code < (uintptr_t)ctx->begin ||
      (uintptr_t)code > (uintptr_t)ctx->end) {
    errno = EINVAL;
    return -1;
  }
  const unsigned char *start = code;
  size_t size = (uintptr_t)ctx->end - (uintptr_t)code + 1;
  uint64_t addr = (uint64_t)code;

  if (size >= sizeof(endbr64) && memcmp(code, endbr64, sizeof(endbr64)) == 0) {
    res.is_set = true;
    res.is_endbr = true;
    res.len = 4;
    *out = res;
    return 0;
  }

  if (!cs_disasm_iter(ctx->handle, &start, &size, &addr, ctx->inst)) {
    cs_err err = cs_errno(ctx->handle);
    if (err != CS_ERR_OK) {
      errno = disasm_wrapper_capstone_errno(err);
      return -1;
    }
    *out = res;
    return 0;
  }

  res.len = ctx->inst->size;

  if (res.len == 0 || res.len > 15 ||
      res.len - 1 > (uintptr_t)ctx->end - (uintptr_t)code ||
      ctx->inst->detail == NULL ||
      ctx->inst->detail->x86.op_count >
          (sizeof(ctx->inst->detail->x86.operands) /
           sizeof(ctx->inst->detail->x86.operands[0]))) {
    errno = EIO;
    return -1;
  }

  res.is_syscall = (ctx->inst->id == X86_INS_SYSCALL);
  res.is_call = (ctx->inst->id == X86_INS_CALL);
  res.is_ret = (ctx->inst->id == X86_INS_RET);

  switch (ctx->inst->id) {
  case X86_INS_JAE:
  case X86_INS_JA:
  case X86_INS_JBE:
  case X86_INS_JB:
  case X86_INS_JCXZ:
  case X86_INS_JECXZ:
  case X86_INS_JE:
  case X86_INS_JGE:
  case X86_INS_JG:
  case X86_INS_JLE:
  case X86_INS_JL:
  case X86_INS_JMP:
  case X86_INS_JNE:
  case X86_INS_JNO:
  case X86_INS_JNP:
  case X86_INS_JNS:
  case X86_INS_JO:
  case X86_INS_JP:
  case X86_INS_JRCXZ:
  case X86_INS_JS:
  case X86_INS_LOOP:
  case X86_INS_LOOPE:
  case X86_INS_LOOPNE:
  case X86_INS_XBEGIN:
  case X86_INS_CALL:
    res.is_jump = true;
    if (ctx->inst->detail->x86.op_count != 1) {
      errno = EIO;
      return -1;
    }
    break;
  case X86_INS_NOP:
    res.is_nop = true;
    break;
  default:
    break;
  }

  /*
   * Loop over all operands of the instruction currently being decoded.
   * These operands are decoded by capstone, and described in the
   * context->inst->detail->x86.operands array.
   *
   * This operand checking serves multiple purposes:
   * The destination of any jumping instruction is found here,
   * The instructions using RIP relative addressing are found by this
   *  loop, e.g.: mov %rax, 0x36eb55d(%rip)
   *
   * Any instruction relying on the value of the RIP register can not
   * be relocated ( including relative jumps, which naturally also
   * rely on the RIP register ).
   */
  for (uint8_t op_i = 0; op_i < ctx->inst->detail->x86.op_count; ++op_i)
    if (disasm_wrapper_check_op(&res, ctx->inst->detail->x86.operands + op_i,
                                code) != 0)
      return -1;

  res.is_lea_rip = (ctx->inst->id == X86_INS_LEA && res.has_ip_relative_opr);

  if (res.is_lea_rip) {
    const cs_x86 *x86 = &ctx->inst->detail->x86;
    if (x86->op_count != 2 || x86->operands[0].type != X86_OP_REG ||
        x86->operands[1].type != X86_OP_MEM ||
        x86->encoding.modrm_offset == 0 ||
        x86->encoding.modrm_offset >= res.len) {
      errno = EIO;
      return -1;
    }
    res.arg_size = x86->operands[0].size;
    if ((res.arg_size != 2 && res.arg_size != 4 && res.arg_size != 8) ||
        (x86->operands[1].mem.base != X86_REG_RIP &&
         x86->operands[1].mem.base != X86_REG_EIP) ||
        x86->operands[1].mem.index != X86_REG_INVALID) {
      errno = EOPNOTSUPP;
      return -1;
    }
    /* Decoded REX/ModRM fields account for absent or extra legacy prefixes. */
    res.arg_register_bits = ((x86->rex & 4) << 1) | ((x86->modrm >> 3) & 7);
  }

  res.is_set = true;

  *out = res;
  return 0;
}
