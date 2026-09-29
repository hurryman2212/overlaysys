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
 * Each selected syscall site jumps to a nearby trampoline containing an
 * absolute jump to its generated wrapper. The wrapper relocates surrounding
 * instructions, calls OverlaySys through intercept_wrapper, then jumps back
 * to the original object. Wrappers and trampolines have separate RX mappings
 * retained by the patch descriptor after text activation.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <sys/mman.h>

#include <cpuid.h>

#include "../util.h"

#include "intercept.h"

/* The size of a trampoline jump, jmp instruction + pointer */
enum { PATCHER_TRAMPOLINE_SIZE = 6 + 8 };

static int patcher_fail(int err) {
  errno = err;
  return -1;
}

static bool patcher_jump_reaches(const void *from, const void *to, size_t size,
                                 uintptr_t forward, uintptr_t backward) {
  uintptr_t origin = (uintptr_t)from;
  uintptr_t target = (uintptr_t)to;
  if (origin > UINTPTR_MAX - size)
    return false;
  origin += size;
  return target >= origin ? target - origin <= forward
                          : origin - target <= backward;
}

/*
 * create_abs_jump(from, to)
 * Create an indirect jump, with the pointer right next to the instruction.
 *
 * jmp *0(%rip)
 *
 * This uses up 6 bytes for the jump instruction, and another 8 bytes
 * for the pointer right after the instruction.
 */
static unsigned char *patcher_create_abs_jump(unsigned char *from, void *to) {
  *from++ = 0xff; /* opcode of RIP based indirect jump */
  *from++ = 0x25; /* opcode of RIP based indirect jump */
  *from++ = 0;    /* 32 bit zero offset */
  *from++ = 0;    /* this means zero relative to the value */
  *from++ = 0;    /* of RIP, which during the execution of the jump */
  *from++ = 0;    /* points to right after the jump instruction */

  unsigned char *d = (unsigned char *)&to;

  *from++ = d[0]; /* so, this is where (RIP + 0) points to, */
  *from++ = d[1]; /* jump reads the destination address */
  *from++ = d[2]; /* from here */
  *from++ = d[3];
  *from++ = d[4];
  *from++ = d[5];
  *from++ = d[6];
  *from++ = d[7];

  return from;
}

/*
 * create_jump(opcode, from, to)
 * Create a 5 byte jmp instruction jumping to address to, by overwriting
 * code starting at address from.
 */
static void patcher_create_jump(unsigned char *from, void *to) {
  /* Distances and destination spans are validated before text is writable. */
  uint32_t delta =
      (uint32_t)((uintptr_t)to - ((uintptr_t)from + JUMP_INST_SIZE));
  from[0] = 0xe9; /* JMP rel32. */
  memcpy(from + 1, &delta, sizeof(delta));
}

/*
 * assign_nop_trampoline
 * Looks for a NOP instruction close to a syscall instruction to be patched.
 * The struct patch_desc argument specifies where the particular syscall
 * instruction resides, and the struct intercept_desc argument of course
 * already contains information about NOPs, collected by the
 * intercept_desc_find_syscalls routine.
 *
 * This routine essentially initializes the uses_nop_trampoline and
 * the nop_trampoline fields of a struct patch_desc.
 */
static void patcher_assign_nop_trampoline(struct intercept_desc *desc,
                                          struct patch_desc *patch,
                                          size_t *next_nop_i) {
  patch->uses_nop_trampoline = false;
  while (*next_nop_i < desc->nop_cnt) {
    const struct range *nop = desc->nop_table + *next_nop_i;
    if (patcher_jump_reaches(patch->syscall_addr, nop->addr + 2,
                             SYSCALL_INST_SIZE, 127, 128)) {
      patch->uses_nop_trampoline = true;
      patch->nop_trampoline = *nop;
      ++*next_nop_i;
      return;
    }
    if (nop->addr > patch->syscall_addr)
      return;
    ++*next_nop_i;
  }
}

/*
 * is_copiable_before_syscall
 * checks if an instruction found before a syscall instruction
 * can be copied (and thus overwritten).
 */
static bool
patcher_is_copiable_before_syscall(struct intercept_disasm_res inst) {
  if (!inst.is_set)
    return false;

  return !(inst.has_ip_relative_opr || inst.is_call || inst.is_rel_jump ||
           inst.is_jump || inst.is_ret || inst.is_endbr || inst.is_syscall);
}

/*
 * is_copiable_after_syscall
 * checks if an instruction found after a syscall instruction
 * can be copied (and thus overwritten).
 *
 * Notice: we allow the copy of ret instructions.
 */
static bool
patcher_is_copiable_after_syscall(struct intercept_disasm_res inst) {
  if (!inst.is_set)
    return false;

  return !(inst.has_ip_relative_opr || inst.is_call || inst.is_rel_jump ||
           inst.is_jump || inst.is_endbr || inst.is_syscall);
}

/*
 * check_surrounding_insts
 * Sets up the following members in a patch_desc, based on
 * instruction being relocateable or not:
 * uses_prev_inst ; uses_prev_inst_2 ; uses_next_inst
 */
static void patcher_check_surrounding_insts(struct intercept_desc *desc,
                                            struct patch_desc *patch) {
  patch->uses_prev_inst =
      (patch->preceding_inst.is_lea_rip ||
       patcher_is_copiable_before_syscall(patch->preceding_inst)) &&
      !intercept_desc_is_overwritable_nop(&patch->preceding_inst) &&
      !intercept_desc_has_jump(desc, patch->syscall_addr);

  if (patch->uses_prev_inst) {
    patch->uses_prev_inst_2 =
        (patch->preceding_inst_2.is_lea_rip ||
         patcher_is_copiable_before_syscall(patch->preceding_inst_2)) &&
        !intercept_desc_is_overwritable_nop(&patch->preceding_inst_2) &&
        !intercept_desc_has_jump(desc, patch->syscall_addr -
                                           patch->preceding_inst.len);
  } else {
    patch->uses_prev_inst_2 = false;
  }

  patch->uses_next_inst =
      (patch->following_inst.is_lea_rip ||
       patcher_is_copiable_after_syscall(patch->following_inst)) &&
      !intercept_desc_is_overwritable_nop(&patch->following_inst) &&
      !intercept_desc_has_jump(desc, patch->syscall_addr + SYSCALL_INST_SIZE);
}

/*
 * Referencing symbols defined in intercept_template.s
 */
extern unsigned char intercept_template_asm_wrapper_tmpl[];
extern unsigned char intercept_template_asm_wrapper_tmpl_end;
extern unsigned char intercept_template_asm_wrapper_patch_desc_addr;
extern unsigned char intercept_template_asm_wrapper_wrapper_level1_addr;
extern unsigned char intercept_wrapper;

size_t patcher_asm_wrapper_tmpl_size;
static ptrdiff_t patcher_o_patch_desc_addr;
static ptrdiff_t patcher_o_wrapper_level1_addr;

/* Assembly tiers: 0 = XSAVE, 1 = FXSAVE, 2 = YMM, 3 = ZMM/opmask. */
unsigned patcher_intercept_xstate_mask;
size_t patcher_intercept_xstate_size = 512;
bool patcher_intercept_xstate_compact;
unsigned patcher_intercept_xstate_tier = 1;
/* XGETBV(1) can prove x87 initial state without storing the FP image. */
bool patcher_intercept_xstate_inuse;
thread_local
    __attribute((tls_model("initial-exec"))) bool patcher_intercept_x87_used;

/*
 * patcher_init
 * Some variables need to be initialized before patching.
 * This routine must be called once before patching any library.
 */
int patcher_init(void) {
  uintptr_t begin = (uintptr_t)intercept_template_asm_wrapper_tmpl;
  uintptr_t end = (uintptr_t)&intercept_template_asm_wrapper_tmpl_end;
  uintptr_t patch_slot =
      (uintptr_t)&intercept_template_asm_wrapper_patch_desc_addr;
  uintptr_t wrapper_slot =
      (uintptr_t)&intercept_template_asm_wrapper_wrapper_level1_addr;
  /* Both template substitutions are ten-byte MOVABS instructions. */
  if (end <= begin || patch_slot < begin || patch_slot > end ||
      end - patch_slot < 10 || wrapper_slot < begin || wrapper_slot > end ||
      end - wrapper_slot < 10)
    return patcher_fail(EIO);
  patcher_asm_wrapper_tmpl_size = end - begin;
  patcher_o_patch_desc_addr = (ptrdiff_t)(patch_slot - begin);
  patcher_o_wrapper_level1_addr = (ptrdiff_t)(wrapper_slot - begin);
  unsigned eax, ebx, ecx, edx;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx & bit_OSXSAVE) &&
      __get_cpuid_max(0, NULL) >= 0xd) {
    unsigned xcr0, high;
    __asm__("xgetbv" : "=a"(xcr0), "=d"(high) : "c"(0));
    __cpuid_count(0xd, 0, eax, ebx, ecx, edx);
    /* Preserve only x87, SSE, AVX and AVX-512 state. PKRU and other syscall
     * effects must not be undone by returning from the machine wrapper. */
    patcher_intercept_xstate_mask = xcr0 & eax & 0xe7;
    patcher_intercept_xstate_size = 576;
    for (unsigned bit = 2; bit <= 7; ++bit) {
      if (!(patcher_intercept_xstate_mask & (1U << bit)))
        continue;
      __cpuid_count(0xd, bit, eax, ebx, ecx, edx);
      size_t end = (size_t)ebx + eax;
      if (end > patcher_intercept_xstate_size)
        patcher_intercept_xstate_size = end;
    }
    __cpuid_count(0xd, 1, eax, ebx, ecx, edx);
    patcher_intercept_xstate_compact = eax & (1U << 1);
    patcher_intercept_xstate_inuse = eax & (1U << 2);
    if (patcher_intercept_xstate_mask & 0xe0) {
      __cpuid_count(7, 0, eax, ebx, ecx, edx);
      patcher_intercept_xstate_tier =
          (patcher_intercept_xstate_mask & 0xe6) == 0xe6 && (ebx & (1U << 30))
              ? 3
              : 0;
      if (patcher_intercept_xstate_tier == 3)
        patcher_intercept_xstate_size = 576 + 32 * 64 + 8 * 8;
    } else if (patcher_intercept_xstate_mask & 4) {
      patcher_intercept_xstate_tier = 2;
      patcher_intercept_xstate_size = 1088;
    }
  }
  if (patcher_intercept_xstate_tier == 1)
    patcher_intercept_xstate_size = 512;
  return 0;
}

/*
 * create_movabs
 * Generates a movabs instruction, that assigns a 64 bit constant to
 * the 64 general purpose register.
 * the reg_bits value must contain the X86 encoding of the register.
 * Returns a pointer to the char right after the generated instruction.
 */
static unsigned char *patcher_create_movabs(unsigned char *code, uint64_t val,
                                            unsigned char reg_bits) {
  if (reg_bits >= 16) {
    errno = EINVAL;
    return NULL;
  }

  unsigned char *bytes = (unsigned char *)&val;

  *code++ = 0x48 | (reg_bits >> 3); /* REX prefix */
  *code++ = 0xb8 | (reg_bits & 7);  /* opcode */
  *code++ = bytes[0];
  *code++ = bytes[1];
  *code++ = bytes[2];
  *code++ = bytes[3];
  *code++ = bytes[4];
  *code++ = bytes[5];
  *code++ = bytes[6];
  *code++ = bytes[7];

  return code;
}

/*
 * relocate_inst
 * Places an instruction equivalent to `inst` to the memory location at `dest`.
 * Only handles instructions that can be copied verbatim, and some LEA
 * instructions.
 */
static unsigned char *
patcher_relocate_inst(unsigned char *dest,
                      const struct intercept_disasm_res *inst) {
  if (!inst->is_set || inst->len == 0 || inst->len > 15 || inst->addr == NULL) {
    errno = EINVAL;
    return NULL;
  }
  if (inst->is_lea_rip) {
    /*
     * Keep LEA's destination width: 16-bit writes preserve upper register
     * bits, 32-bit writes zero them, and 64-bit writes use the whole address.
     * Address-size truncation is already reflected in rip_ref_addr.
     */
    const uint64_t val = (uintptr_t)inst->rip_ref_addr;
    if (inst->arg_size == 8)
      return patcher_create_movabs(dest, val, inst->arg_register_bits);
    if ((inst->arg_size != 2 && inst->arg_size != 4) ||
        inst->arg_register_bits >= 16) {
      errno = EINVAL;
      return NULL;
    }
    if (inst->arg_size == 2)
      *dest++ = 0x66;
    if (inst->arg_register_bits >= 8)
      *dest++ = 0x41; /* REX.B selects the extended destination register. */
    *dest++ = 0xb8 | (inst->arg_register_bits & 7);
    memcpy(dest, &val, inst->arg_size);
    return dest + inst->arg_size;
  } else {
    memcpy(dest, inst->addr, inst->len);
    return dest + inst->len;
  }
}

/*
 * create_wrapper
 * Generates an assembly wrapper. Copies the template written in
 * intercept_template.s, and generates the instructions specific
 * to a particular syscall into the new copy.
 * The engine makes this mapping executable before patcher_activate_patches
 * publishes a jump to it. The template calls intercept_wrapper with the saved
 * context.
 */
static int patcher_create_wrapper(struct patch_desc *patch,
                                  unsigned char **dest) {
  patch->asm_wrapper = *dest;
  unsigned char *next;
  if (patch->uses_prev_inst) {
    if (patch->uses_prev_inst_2) {
      next = patcher_relocate_inst(*dest, &patch->preceding_inst_2);
      if (next == NULL)
        return -1;
      *dest = next;
    }
    next = patcher_relocate_inst(*dest, &patch->preceding_inst);
    if (next == NULL)
      return -1;
    *dest = next;
  }
  memcpy(*dest, intercept_template_asm_wrapper_tmpl,
         patcher_asm_wrapper_tmpl_size);
  if (patcher_create_movabs(*dest + patcher_o_patch_desc_addr, (uintptr_t)patch,
                            11) == NULL ||
      patcher_create_movabs(*dest + patcher_o_wrapper_level1_addr,
                            (uintptr_t)&intercept_wrapper, 11) == NULL)
    return -1;
  *dest += patcher_asm_wrapper_tmpl_size;
  if (patch->uses_next_inst) {
    next = patcher_relocate_inst(*dest, &patch->following_inst);
    if (next == NULL)
      return -1;
    *dest = next;
  }
  *dest = patcher_create_abs_jump(*dest, patch->return_addr);
  return 0;
}

/*
 * patcher_create_patch_wrappers - create the custom assembly wrappers
 * around each syscall to be intercepted. Well, actually, the
 * function create_wrapper does that, so perhaps this function
 * deserves a better name.
 * What this function actually does, is figure out how to create
 * a jump instruction in libc ( which bytes to overwrite ).
 * If it successfully finds suitable bytes for hotpatching,
 * then it determines the exact bytes to overwrite, and the exact
 * address for jumping back to libc.
 *
 * This is all based on the information collected by the routine
 * intercept_desc_find_syscalls, which does the disassembling, finding jump
 * destinations, finding padding bytes, etc..
 */
int patcher_create_patch_wrappers(struct intercept_desc *desc,
                                  unsigned char **dest) {
  if (desc->text_written)
    return patcher_fail(EBUSY);
  if (desc->cnt == 0)
    return 0;
  if (dest == NULL || *dest == NULL || desc->items == NULL ||
      desc->cnt > desc->items_size / sizeof(*desc->items) ||
      desc->jump_table == NULL || desc->nop_cnt > desc->max_nop_cnt ||
      (desc->nop_cnt != 0 && desc->nop_table == NULL) ||
      patcher_asm_wrapper_tmpl_size == 0)
    return patcher_fail(EINVAL);
  size_t next_nop_i = 0;

  for (unsigned patch_i = 0; patch_i < desc->cnt; ++patch_i) {
    struct patch_desc *patch = desc->items + patch_i;

    patcher_assign_nop_trampoline(desc, patch, &next_nop_i);

    if (patch->uses_nop_trampoline) {
      /*
       * The preferred option it to use a 5 byte relative
       * jump in a padding space between symbols in libc.
       * If such padding space is found, a 2 byte short
       * jump is enough for jumping to it, thus no
       * instructions other than the syscall
       * itself need to be overwritten.
       */
      patch->uses_prev_inst = false;
      patch->uses_prev_inst_2 = false;
      patch->uses_next_inst = false;
      patch->dest_jmp_patch = patch->nop_trampoline.addr + 2;
      /*
       * The first two bytes of the nop are used for
       * something else, see the explanation
       * at intercept_desc_is_overwritable_nop in intercept_desc.c
       */

      /*
       * Return to libc:
       * just jump to instruction right after the place
       * where the syscall instruction was originally.
       */
      patch->return_addr = patch->syscall_addr + SYSCALL_INST_SIZE;

    } else {
      /*
       * No padding space is available, so check the
       * instructions surrounding the syscall instruction.
       * If they can be relocated, then they can be
       * overwritten. Of course some instructions depend
       * on the value of the RIP register, these can not
       * be relocated.
       */

      patcher_check_surrounding_insts(desc, patch);

      /*
       * Count the number of overwritable bytes
       * in the variable length.
       * Sum up the bytes that can be overwritten.
       * The 2 bytes of the syscall instruction can
       * be overwritten definitely, so length starts
       * as SYSCALL_INST_SIZE ( 2 bytes ).
       */
      unsigned len = SYSCALL_INST_SIZE;

      patch->dest_jmp_patch = patch->syscall_addr;

      /*
       * If the preceding instruction is relocatable,
       * add its length. Also, the the instruction right
       * before that.
       */
      if (patch->uses_prev_inst) {
        len += patch->preceding_inst.len;
        patch->dest_jmp_patch -= patch->preceding_inst.len;

        if (patch->uses_prev_inst_2) {
          len += patch->preceding_inst_2.len;
          patch->dest_jmp_patch -= patch->preceding_inst_2.len;
        }
      }

      /*
       * If the following instruction is relocatable,
       * add its length. This also affects the return address.
       * Normally, the library would return to libc after
       * handling the syscall by jumping to instruction
       * right after the syscall. But if that instruction
       * is overwritten, the returning jump must jump to
       * the instruction after it.
       */
      if (patch->uses_next_inst) {
        len += patch->following_inst.len;

        /*
         * Address of the syscall instruction
         * plus 2 bytes
         * plus the length of the following instruction
         *
         * adds up to:
         *
         * the address of the second instruction after
         * the syscall.
         */
        patch->return_addr =
            patch->syscall_addr + SYSCALL_INST_SIZE + patch->following_inst.len;
      } else {
        /*
         * Address of the syscall instruction
         * plus 2 bytes
         *
         * adds up to:
         *
         * the address of the first instruction after
         * the syscall ( just like in the case of
         * using padding bytes ).
         */
        patch->return_addr = patch->syscall_addr + SYSCALL_INST_SIZE;
      }

      /*
       * If the length is at least 5, then a jump instruction
       * with a 32 bit displacement can fit.
       *
       * Otherwise give up
       */
      if (len < JUMP_INST_SIZE)
        return patcher_fail(EOPNOTSUPP);
    }

    intercept_desc_mark_jump(desc, patch->return_addr);

    if (patcher_create_wrapper(patch, dest) != 0)
      return -1;
  }
  return 0;
}

/*
 * create_short_jump
 * Generates a 2 byte jump instruction. The to address must be reachable
 * using an 8 bit displacement.
 */
static void patcher_create_short_jump(unsigned char *from, unsigned char *to) {
  from[0] = 0xeb; /* JMP rel8. */
  from[1] = (unsigned char)((uintptr_t)to - ((uintptr_t)from + 2));
}

int patcher_prepare_trampolines(struct intercept_desc *desc) {
  if (desc->text_written)
    return patcher_fail(EBUSY);
  if (desc->cnt == 0)
    return 0;
  size_t bytes = (size_t)desc->cnt * PATCHER_TRAMPOLINE_SIZE;
  if (desc->trampoline_table == NULL || desc->trampoline_table_size < bytes ||
      desc->items == NULL ||
      desc->cnt > desc->items_size / sizeof(*desc->items))
    return patcher_fail(EINVAL);
  for (unsigned i = 0; i < desc->cnt; ++i) {
    if (desc->items[i].asm_wrapper == NULL)
      return patcher_fail(EINVAL);
  }
  unsigned char *next = desc->trampoline_table;
  for (unsigned i = 0; i < desc->cnt; ++i)
    next = patcher_create_abs_jump(next, desc->items[i].asm_wrapper);
  return util_mprotect_no_intercept(desc->trampoline_table,
                                    desc->trampoline_table_size,
                                    PROT_READ | PROT_EXEC);
}

/* All checks below precede the first text write. No failure path after text
 * publication may release wrappers, descriptors, or trampoline allocations. */
int patcher_activate_patches(struct intercept_desc *desc) {
  if (desc->cnt == 0)
    return 0;
  uintptr_t start = (uintptr_t)desc->text_start;
  uintptr_t end = (uintptr_t)desc->text_end;
  if (start == 0 || end < start || end == UINTPTR_MAX)
    return patcher_fail(EINVAL);
  unsigned char *first_page = (void *)(start & ~(PAGE_SIZE - 1));
  size_t size = end - (uintptr_t)first_page + 1;
  if (desc->text_written)
    return util_mprotect_no_intercept(first_page, size, PROT_READ | PROT_EXEC);
  if (desc->items == NULL ||
      desc->cnt > desc->items_size / sizeof(*desc->items) ||
      desc->trampoline_table == NULL ||
      desc->trampoline_table_size < (size_t)desc->cnt * PATCHER_TRAMPOLINE_SIZE)
    return patcher_fail(EINVAL);
  for (unsigned i = 0; i < desc->cnt; ++i) {
    const struct patch_desc *patch = desc->items + i;
    uintptr_t site = (uintptr_t)patch->syscall_addr;
    uintptr_t jump = (uintptr_t)patch->dest_jmp_patch;
    uintptr_t resume = (uintptr_t)patch->return_addr;
    if (site < start || site > end || end - site < SYSCALL_INST_SIZE - 1 ||
        jump < start || jump > end || end - jump < JUMP_INST_SIZE - 1 ||
        resume < start || resume > end + 1 || patch->asm_wrapper == NULL)
      return patcher_fail(EINVAL);
    if (patch->syscall_addr[0] != 0x0f || patch->syscall_addr[1] != 0x05)
      return patcher_fail(ESTALE);
    unsigned char *trampoline =
        desc->trampoline_table + (size_t)i * PATCHER_TRAMPOLINE_SIZE;
    if (!patcher_jump_reaches(patch->dest_jmp_patch, trampoline, JUMP_INST_SIZE,
                              INT32_MAX, (uintptr_t)INT32_MAX + 1))
      return patcher_fail(ERANGE);
    if (patch->uses_nop_trampoline) {
      uintptr_t nop = (uintptr_t)patch->nop_trampoline.addr;
      size_t nop_size = patch->nop_trampoline.size;
      if (nop < start || nop > end || nop_size < 2 + JUMP_INST_SIZE ||
          nop_size > end - nop + 1 || jump != nop + 2 ||
          resume != site + SYSCALL_INST_SIZE)
        return patcher_fail(EINVAL);
      if (!patcher_jump_reaches(patch->syscall_addr, patch->dest_jmp_patch,
                                SYSCALL_INST_SIZE, 127, 128) ||
          !patcher_jump_reaches(patch->nop_trampoline.addr,
                                (void *)(nop + nop_size), 2, 127, 128))
        return patcher_fail(ERANGE);
    } else if (jump > site || resume < site + SYSCALL_INST_SIZE ||
               resume - jump < JUMP_INST_SIZE) {
      return patcher_fail(EINVAL);
    }
  }
  if (util_mprotect_no_intercept(first_page, size,
                                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return -1;
  for (unsigned i = 0; i < desc->cnt; ++i) {
    const struct patch_desc *patch = desc->items + i;
    patcher_create_jump(patch->dest_jmp_patch,
                        desc->trampoline_table +
                            (size_t)i * PATCHER_TRAMPOLINE_SIZE);
    if (patch->uses_nop_trampoline) {
      patcher_create_short_jump(patch->syscall_addr, patch->dest_jmp_patch);
      patcher_create_short_jump(patch->nop_trampoline.addr,
                                patch->nop_trampoline.addr +
                                    patch->nop_trampoline.size);
    } else {
      for (unsigned char *byte = patch->dest_jmp_patch + JUMP_INST_SIZE;
           byte < patch->return_addr; ++byte)
        *byte = 0xcc; /* INT3 traps unexpected entry into overwritten bytes. */
    }
  }
  desc->text_written = true;
  return util_mprotect_no_intercept(first_page, size, PROT_READ | PROT_EXEC);
}
