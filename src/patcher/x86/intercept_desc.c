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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "../patcher.h"
#include "../util.h"

#include "intercept.h"

/* Existing padding-table allocation estimates. */
static const size_t intercept_desc_nop_estimate_threshold = 0x10000;
static const size_t intercept_desc_nop_estimate_bytes_per_entry = 64;
static const size_t intercept_desc_nop_estimate_min_entries = 1024;

static int intercept_desc_fail(int err) {
  errno = err;
  return -1;
}

static int intercept_desc_add_table_info(struct section_list *list,
                                         const Elf64_Shdr *header) {
  if (list->cnt >= sizeof(list->headers) / sizeof(list->headers[0]))
    return intercept_desc_fail(E2BIG);
  list->headers[list->cnt++] = *header;
  return 0;
}

/* Section and symbol buffers are temporary; persistent model allocations stay
 * on the descriptor until intercept_desc_release successfully unmaps them. */
static int intercept_desc_find_sections(struct intercept_desc *desc, int fd) {
  Elf64_Ehdr header;
  if (util_xread(fd, &header, sizeof(header)) != 0)
    return -1;
  if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64 ||
      header.e_type != ET_DYN || header.e_shnum == 0 ||
      header.e_shentsize != sizeof(Elf64_Shdr))
    return intercept_desc_fail(ENOEXEC);
  struct stat file;
  int err =
      patcher_syscall_err_code(util_syscall_no_intercept(SYS_fstat, fd, &file));
  if (err != 0)
    return intercept_desc_fail(err);
  size_t bytes = header.e_shnum * sizeof(Elf64_Shdr);
  if (file.st_size < 0 || header.e_shoff > (uint64_t)file.st_size ||
      bytes > (uint64_t)file.st_size - header.e_shoff)
    return intercept_desc_fail(ENOEXEC);
  Elf64_Shdr *sections = malloc(bytes);
  if (sections == NULL)
    return intercept_desc_fail(ENOMEM);
  if (util_xlseek(fd, header.e_shoff, SEEK_SET) < 0 ||
      util_xread(fd, sections, bytes) != 0) {
    err = errno;
    goto out;
  }
  for (Elf64_Half i = 0; i < header.e_shnum; ++i) {
    const Elf64_Shdr *section = sections + i;
    if (section->sh_type != SHT_NOBITS &&
        (section->sh_offset > (uint64_t)file.st_size ||
         section->sh_size > (uint64_t)file.st_size - section->sh_offset)) {
      err = ENOEXEC;
      goto out;
    }
    if ((section->sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) ==
            (SHF_ALLOC | SHF_EXECINSTR) &&
        section->sh_size != 0) {
      if (section->sh_addr > UINTPTR_MAX - (uintptr_t)desc->base_addr) {
        err = ENOEXEC;
        goto out;
      }
      uintptr_t addr = (uintptr_t)desc->base_addr + section->sh_addr;
      if (section->sh_type != SHT_PROGBITS ||
          addr < (uintptr_t)desc->text_start ||
          addr > (uintptr_t)desc->text_end ||
          section->sh_size - 1 > (uintptr_t)desc->text_end - addr) {
        err = ENOEXEC;
        goto out;
      }
      if (intercept_desc_add_table_info(&desc->code_sections, section) != 0) {
        err = errno;
        goto out;
      }
    }
    if (section->sh_type == SHT_SYMTAB || section->sh_type == SHT_DYNSYM) {
      if (section->sh_size % sizeof(Elf64_Sym) != 0) {
        err = ENOEXEC;
        goto out;
      }
      if (intercept_desc_add_table_info(&desc->symbol_tables, section) != 0) {
        err = errno;
        goto out;
      }
    } else if (section->sh_type == SHT_RELA) {
      if (section->sh_size % sizeof(Elf64_Rela) != 0) {
        err = ENOEXEC;
        goto out;
      }
      if (intercept_desc_add_table_info(&desc->rela_tables, section) != 0) {
        err = errno;
        goto out;
      }
    }
  }
out:
  free(sections);
  return err != 0 ? intercept_desc_fail(err) : 0;
}

bool intercept_desc_has_jump(const struct intercept_desc *desc,
                             const unsigned char *ptr) {
  uintptr_t addr = (uintptr_t)ptr;
  if (addr < (uintptr_t)desc->text_start || addr > (uintptr_t)desc->text_end)
    return false;
  uintptr_t off = addr - (uintptr_t)desc->text_start;
  return desc->jump_table[off / 8] & (1U << (off % 8));
}

void intercept_desc_mark_jump(const struct intercept_desc *desc,
                              const unsigned char *ptr) {
  uintptr_t addr = (uintptr_t)ptr;
  if (addr >= (uintptr_t)desc->text_start &&
      addr <= (uintptr_t)desc->text_end) {
    uintptr_t off = addr - (uintptr_t)desc->text_start;
    desc->jump_table[off / 8] |= (unsigned char)(1U << (off % 8));
  }
}

static int intercept_desc_find_jumps_in_section(struct intercept_desc *desc,
                                                const Elf64_Shdr *section,
                                                int fd) {
  if (section->sh_type != SHT_SYMTAB && section->sh_type != SHT_DYNSYM &&
      section->sh_type != SHT_RELA)
    return intercept_desc_fail(EINVAL);
  if (section->sh_size == 0)
    return 0;
  void *buf = malloc(section->sh_size);
  if (buf == NULL)
    return intercept_desc_fail(ENOMEM);
  int err = 0;
  if (util_xlseek(fd, section->sh_offset, SEEK_SET) < 0 ||
      util_xread(fd, buf, section->sh_size) != 0) {
    err = errno;
    goto out;
  }
  if (section->sh_type == SHT_RELA) {
    const Elf64_Rela *relocations = buf;
    for (size_t i = 0; i < section->sh_size / sizeof(*relocations); ++i) {
      unsigned type = ELF64_R_TYPE(relocations[i].r_info);
      if (type == R_X86_64_RELATIVE || type == R_X86_64_RELATIVE64)
        intercept_desc_mark_jump(desc,
                                 (void *)((uintptr_t)desc->base_addr +
                                          (uintptr_t)relocations[i].r_addend));
    }
  } else {
    const Elf64_Sym *symbols = buf;
    for (size_t i = 0; i < section->sh_size / sizeof(*symbols); ++i) {
      if (ELF64_ST_TYPE(symbols[i].st_info) != STT_FUNC ||
          symbols[i].st_shndx == SHN_UNDEF)
        continue;
      uintptr_t addr = (uintptr_t)desc->base_addr + symbols[i].st_value;
      intercept_desc_mark_jump(desc, (void *)addr);
      if (symbols[i].st_size != 0 && symbols[i].st_size <= UINTPTR_MAX - addr)
        intercept_desc_mark_jump(desc, (void *)(addr + symbols[i].st_size));
    }
  }
out:
  free(buf);
  return err != 0 ? intercept_desc_fail(err) : 0;
}

static struct patch_desc *
intercept_desc_add_new_patch(struct intercept_desc *desc) {
  if (desc->cnt == UINT_MAX) {
    errno = EOVERFLOW;
    return NULL;
  }
  size_t capacity = desc->items_size / sizeof(*desc->items);
  if (desc->cnt == capacity) {
    if (desc->items_size > SIZE_MAX / 2) {
      errno = EOVERFLOW;
      return NULL;
    }
    size_t bytes =
        desc->items_size ? desc->items_size * 2 : sizeof(*desc->items);
    void *items = desc->items == NULL
                      ? util_xmmap_anon(bytes)
                      : util_xmremap(desc->items, desc->items_size, bytes);
    if (items == NULL)
      return NULL;
    desc->items = items;
    desc->items_size = bytes;
  }
  struct patch_desc *patch = desc->items + desc->cnt++;
  memset(patch, 0, sizeof(*patch));
  return patch;
}

bool intercept_desc_is_overwritable_nop(
    const struct intercept_disasm_res *inst) {
  return inst->is_nop && inst->len >= 2 + JUMP_INST_SIZE;
}

static int intercept_desc_crawl_text(struct intercept_desc *desc,
                                     const Elf64_Shdr *section) {
  unsigned char *begin =
      (void *)((uintptr_t)desc->base_addr + section->sh_addr);
  unsigned char *end = begin + section->sh_size - 1;
  unsigned char *code = begin;
  struct intercept_disasm_res prevs[3] = {0};
  int err = 0;
  if (disasm_wrapper_init(begin, end, &desc->disasm) != 0) {
    err = errno;
    goto out;
  }
  while (code <= end) {
    struct intercept_disasm_res res;
    if (disasm_wrapper_next_inst(desc->disasm, code, &res) != 0) {
      err = errno;
      goto out;
    }
    if (res.len == 0) {
      if (prevs[2].is_syscall) {
        err = EOPNOTSUPP;
        goto out;
      }
      memset(prevs, 0, sizeof(prevs));
      ++code;
      continue;
    }
    if (res.has_ip_relative_opr)
      intercept_desc_mark_jump(desc, res.rip_ref_addr);
    if (intercept_desc_is_overwritable_nop(&res) &&
        desc->nop_cnt < desc->max_nop_cnt)
      desc->nop_table[desc->nop_cnt++] = (struct range){code, res.len};
    if (prevs[2].is_syscall) {
      struct patch_desc *patch = intercept_desc_add_new_patch(desc);
      if (patch == NULL) {
        err = errno;
        goto out;
      }
      patch->preceding_inst_2 = prevs[0];
      patch->preceding_inst = prevs[1];
      patch->following_inst = res;
      patch->syscall_addr = code - SYSCALL_INST_SIZE;
    }
    prevs[0] = prevs[1];
    prevs[1] = prevs[2];
    prevs[2] = res;
    code += res.len;
  }
  if (prevs[2].is_syscall)
    err = EOPNOTSUPP;
out:
  if (desc->disasm != NULL) {
    if (disasm_wrapper_destroy(desc->disasm) != 0) {
      if (err == 0)
        err = errno;
    } else {
      desc->disasm = NULL;
    }
  }
  return err != 0 ? intercept_desc_fail(err) : 0;
}

int intercept_desc_alloc_trampoline_table(struct intercept_desc *desc) {
  if (desc->cnt == 0 || desc->trampoline_table != NULL)
    return intercept_desc_fail(EINVAL);
  size_t size = ((size_t)desc->cnt * 14 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
  uintptr_t low = (uintptr_t)desc->text_end > INT32_MAX
                      ? (uintptr_t)desc->text_end - INT32_MAX
                      : PAGE_SIZE;
  if (low > UINTPTR_MAX - PAGE_SIZE + 1 ||
      (uintptr_t)desc->text_start > UINTPTR_MAX - INT32_MAX)
    return intercept_desc_fail(EOVERFLOW);
  low = (low + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
  uintptr_t high = (uintptr_t)desc->text_start + INT32_MAX;
  if (high <= low || size >= high - low)
    return intercept_desc_fail(ERANGE);
  FILE *maps = fopen("/proc/self/maps", "re");
  if (maps == NULL)
    return -1;
  char *line = NULL;
  size_t capacity = 0;
  uintptr_t guess = low;
  int err = 0;
  bool allocated = false;
  while (getline(&line, &capacity, maps) >= 0) {
    uintptr_t start, end;
    if (sscanf(line, "%lx-%lx", &start, &end) != 2 || end < start) {
      err = EIO;
      goto out;
    }
    if (end <= guess)
      continue;
    if (start >= guess && size <= start - guess && guess <= high - size) {
      long res = util_syscall_no_intercept(SYS_mmap, (void *)guess, size,
                                           PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0L);
      err = patcher_syscall_err_code(res);
      if (err != 0)
        goto out;
      /* Keep ownership visible even if rejecting this location fails to unmap.
       */
      desc->trampoline_table = (void *)res;
      desc->trampoline_table_size = size;
      uintptr_t placed = (uintptr_t)res;
      if (placed >= low && placed <= high - size) {
        allocated = true;
        break;
      }
      if (util_xmunmap(desc->trampoline_table, size) != 0) {
        err = errno;
        goto out;
      }
      desc->trampoline_table = NULL;
      desc->trampoline_table_size = 0;
    }
    if (end > guess)
      guess = end;
    if (guess > high - size)
      break;
  }
  if (ferror(maps))
    err = errno ? errno : EIO;
  if (err == 0 && !allocated)
    err = ENOMEM;
out:
  free(line);
  if (fclose(maps) != 0 && err == 0)
    err = errno ? errno : EIO;
  if (err != 0)
    return intercept_desc_fail(err);
  return 0;
}

int intercept_desc_release(struct intercept_desc *desc) {
  if (desc->text_written)
    return intercept_desc_fail(EBUSY);
  int err = 0;
  if (desc->disasm != NULL) {
    if (disasm_wrapper_destroy(desc->disasm) != 0)
      err = errno;
    else
      desc->disasm = NULL;
  }
  if (desc->items != NULL) {
    if (util_xmunmap(desc->items, desc->items_size) != 0) {
      if (err == 0)
        err = errno;
    } else {
      desc->items = NULL;
      desc->items_size = 0;
    }
  }
  if (desc->jump_table != NULL) {
    if (util_xmunmap(desc->jump_table, desc->jump_table_size) != 0) {
      if (err == 0)
        err = errno;
    } else {
      desc->jump_table = NULL;
      desc->jump_table_size = 0;
    }
  }
  if (desc->nop_table != NULL) {
    if (util_xmunmap(desc->nop_table, desc->nop_table_size) != 0) {
      if (err == 0)
        err = errno;
    } else {
      desc->nop_table = NULL;
      desc->nop_table_size = 0;
    }
  }
  if (desc->trampoline_table != NULL) {
    if (util_xmunmap(desc->trampoline_table, desc->trampoline_table_size) !=
        0) {
      if (err == 0)
        err = errno;
    } else {
      desc->trampoline_table = NULL;
      desc->trampoline_table_size = 0;
    }
  }
  if (err != 0)
    return intercept_desc_fail(err);
  desc->cnt = 0;
  desc->code_sections.cnt = 0;
  desc->symbol_tables.cnt = 0;
  desc->rela_tables.cnt = 0;
  desc->nop_cnt = desc->max_nop_cnt = 0;
  return 0;
}

int intercept_desc_find_syscalls(struct intercept_desc *desc) {
  if (desc->text_written || desc->items != NULL || desc->jump_table != NULL ||
      desc->nop_table != NULL || desc->trampoline_table != NULL ||
      desc->disasm != NULL)
    return intercept_desc_fail(EBUSY);
  uintptr_t start = (uintptr_t)desc->text_start;
  uintptr_t end = (uintptr_t)desc->text_end;
  if (start == 0 || end < start || end - start == SIZE_MAX)
    return intercept_desc_fail(ENOEXEC);
  long opened = util_syscall_no_intercept(SYS_openat, AT_FDCWD, desc->path,
                                          O_RDONLY | O_CLOEXEC);
  int err = patcher_syscall_err_code(opened);
  if (err != 0)
    return intercept_desc_fail(err);
  int fd = (int)opened;
  struct stat file;
  err =
      patcher_syscall_err_code(util_syscall_no_intercept(SYS_fstat, fd, &file));
  if (err != 0)
    goto out;
  if (!S_ISREG(file.st_mode) || file.st_dev != desc->dev ||
      file.st_ino != desc->inode) {
    err = ESTALE;
    goto out;
  }
  if (intercept_desc_find_sections(desc, fd) != 0) {
    err = errno;
    goto out;
  }
  size_t bytes = end - start + 1;
  desc->jump_table_size = bytes / 8 + 1;
  desc->jump_table = util_xmmap_anon(desc->jump_table_size);
  if (desc->jump_table == NULL) {
    desc->jump_table_size = 0;
    err = errno;
    goto out;
  }
  /* Retain the original padding-table sizing heuristic. */
  desc->max_nop_cnt = bytes > intercept_desc_nop_estimate_threshold
                          ? bytes / intercept_desc_nop_estimate_bytes_per_entry
                          : intercept_desc_nop_estimate_min_entries;
  if (desc->max_nop_cnt > SIZE_MAX / sizeof(*desc->nop_table)) {
    err = EOVERFLOW;
    goto out;
  }
  desc->nop_table_size = desc->max_nop_cnt * sizeof(*desc->nop_table);
  desc->nop_table = util_xmmap_anon(desc->nop_table_size);
  if (desc->nop_table == NULL) {
    desc->nop_table_size = 0;
    err = errno;
    goto out;
  }
  for (Elf64_Half i = 0; i < desc->symbol_tables.cnt; ++i) {
    if (intercept_desc_find_jumps_in_section(
            desc, desc->symbol_tables.headers + i, fd) != 0) {
      err = errno;
      goto out;
    }
  }
  for (Elf64_Half i = 0; i < desc->rela_tables.cnt; ++i) {
    if (intercept_desc_find_jumps_in_section(
            desc, desc->rela_tables.headers + i, fd) != 0) {
      err = errno;
      goto out;
    }
  }
  for (Elf64_Half i = 0; i < desc->code_sections.cnt; ++i) {
    const Elf64_Shdr *section = desc->code_sections.headers + i;
    uintptr_t begin = (uintptr_t)desc->base_addr + section->sh_addr;
    intercept_desc_mark_jump(desc, (void *)begin);
    intercept_desc_mark_jump(desc, (void *)(begin + section->sh_size));
    if (intercept_desc_crawl_text(desc, section) != 0) {
      err = errno;
      goto out;
    }
  }
out: {
  int close_err =
      patcher_syscall_err_code(util_syscall_no_intercept(SYS_close, fd));
  if (err == 0)
    err = close_err;
}
  return err != 0 ? intercept_desc_fail(err) : 0;
}
