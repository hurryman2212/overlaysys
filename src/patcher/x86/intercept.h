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

/* Shared x86 patch discovery, relocation, and activation state. */

#ifndef INTERCEPT_INTERCEPT_H
#define INTERCEPT_INTERCEPT_H

#include <stddef.h>

#include <sys/types.h>

#include <elf.h>

#include "disasm_wrapper.h"

struct range {
  unsigned char *addr;
  size_t size;
};

/* One syscall site and its generated wrapper, text replacement, and return. */
struct patch_desc {
  /* the original syscall instruction */
  unsigned char *syscall_addr;

  /* the new asm wrapper created */
  unsigned char *asm_wrapper;

  /* the first byte overwritten in the code */
  unsigned char *dest_jmp_patch;

  /* the address to jump back to */
  unsigned char *return_addr;

  /*
   * Describe up to three instructions surrounding the original
   * syscall instructions. Sometimes just overwritting the two
   * direct neighbors of the syscall is not enough, ( e.g. if
   * both the directly preceding, and the directly following are
   * single byte instruction, that only gives 4 bytes of space ).
   */
  struct intercept_disasm_res preceding_inst_2;
  struct intercept_disasm_res preceding_inst;
  struct intercept_disasm_res following_inst;
  bool uses_prev_inst_2;
  bool uses_prev_inst;
  bool uses_next_inst;

  bool uses_nop_trampoline;

  struct range nop_trampoline;
};

/*
 * ELF code, symbol, and relocation sections used to identify instruction
 * boundaries and jump targets. Reject objects exceeding 16 sections per kind.
 */
struct section_list {
  Elf64_Half cnt;
  Elf64_Shdr headers[0x10];
};

struct intercept_desc {
  dev_t dev;
  ino_t inode;

  /* Once true, activation retries only the final RX permission restore. */
  bool text_written;
  struct disasm_wrapper_ctx *disasm;

  /*
   * delta between vmem addresses and addresses in symbol tables,
   * non-zero for dynamic objects
   */
  unsigned char *base_addr;

  /* where the object is in fs */
  const char *path;

  /*
   * Some sections of the library from which information
   * needs to be extracted.
   * The text section is where the code to be hotpatched
   * resides.
   * The symtab, and dynsym sections provide information on
   * the whereabouts of symbols, whose address in the text
   * section.
   */
  struct section_list code_sections;
  struct section_list symbol_tables;
  struct section_list rela_tables;

  /*
   * Where the text starts and ends in the virtual memory seen by the
   * current process.
   */
  unsigned char *text_start;
  unsigned char *text_end;

  struct patch_desc *items;
  size_t items_size;
  unsigned cnt;
  unsigned char *jump_table;
  size_t jump_table_size;

  size_t nop_cnt;
  size_t max_nop_cnt;
  struct range *nop_table;
  size_t nop_table_size;

  unsigned char *trampoline_table;
  size_t trampoline_table_size;
};

bool intercept_desc_has_jump(const struct intercept_desc *desc,
                             const unsigned char *ptr);
void intercept_desc_mark_jump(const struct intercept_desc *desc,
                              const unsigned char *ptr);
bool intercept_desc_is_overwritable_nop(
    const struct intercept_disasm_res *inst);

int intercept_desc_alloc_trampoline_table(struct intercept_desc *desc);
int intercept_desc_release(struct intercept_desc *desc);
int intercept_desc_find_syscalls(struct intercept_desc *desc);

/* The size of an asm wrapper instance, initialized by patcher_init. */
extern size_t patcher_asm_wrapper_tmpl_size;

int patcher_init(void);
int patcher_create_patch_wrappers(struct intercept_desc *desc,
                                  unsigned char **dest);

/* Populate the trampoline mapping, then publish the selected text patches. */
int patcher_prepare_trampolines(struct intercept_desc *desc);
int patcher_activate_patches(struct intercept_desc *desc);

#define SYSCALL_INST_SIZE 2
#define JUMP_INST_SIZE 5
#define PAGE_SIZE ((size_t)0x1000)

#endif
