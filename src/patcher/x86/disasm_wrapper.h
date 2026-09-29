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

/* Decoder-independent instruction properties used by patch discovery and
 * relocation. Capstone state stays private to disasm_wrapper.c. */

#ifndef INTERCEPT_DISASM_WRAPPER_H
#define INTERCEPT_DISASM_WRAPPER_H

struct intercept_disasm_res {
  const unsigned char *addr;

  bool is_set;

  bool is_syscall;

  /* Length in bytes, zero if disasm was not successful. */
  unsigned len;

  /*
   * Flag marking instructions that have a RIP relative address
   * as an operand.
   */
  bool has_ip_relative_opr;

  /* as of now this only refers to endbr64 */
  bool is_endbr;

  /*
   * LEA with an instruction-pointer-relative source. Relocation substitutes
   * an immediate move with the original destination width.
   */
  bool is_lea_rip;

  /*
   * Encoded destination register (0..15) and size in bytes (2, 4, or 8),
   * valid when is_lea_rip is set.
   */
  unsigned char arg_register_bits;
  unsigned char arg_size;

  /* call instruction */
  bool is_call;

  bool is_jump;

  /*
   * The flag is_rel_jump marks any instruction that jumps, to
   * a relative address encoded in its operand.
   * This includes call as well.
   */
  bool is_rel_jump;

  bool is_indirect_jump;

  bool is_ret;

  bool is_nop;

  /* Absolute reference target, valid when has_ip_relative_opr is true. */
  const unsigned char *rip_ref_addr;
};

struct disasm_wrapper_ctx;

/* Any allocated context remains in *out, including on failure. */
int disasm_wrapper_init(const unsigned char *begin, const unsigned char *end,
                        struct disasm_wrapper_ctx **out);

/* Returns -1 with errno on failure; an unfreed context remains caller-owned. */
int disasm_wrapper_destroy(struct disasm_wrapper_ctx *ctx);

/* Undecodable bytes produce a zero-length result and return 0. */
int disasm_wrapper_next_inst(struct disasm_wrapper_ctx *ctx,
                             const unsigned char *code,
                             struct intercept_disasm_res *out);

#endif
