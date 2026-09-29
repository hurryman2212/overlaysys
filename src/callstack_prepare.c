#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <unistd.h>

#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <dwarf.h>
#include <gelf.h>

#include "callstack.h"
#include "internal.h"

/* Bound preparation of expressions that the allocation-free reader can use. */
static const size_t callstack_max_expression_ops = 256;

_Atomic(struct callstack_module *) callstack_modules;
_Atomic bool callstack_ready;
static _Atomic bool callstack_prepare_busy;

struct callstack_preparation {
  struct callstack_module *existing;
  struct callstack_module *pending;
  int error;
};

static void callstack_row_release(struct callstack_row *row) {
  free(row->cfa.ops);
  for (size_t i = 0; i < CALLSTACK_REGISTERS; ++i)
    free(row->registers[i].expression.ops);
}

static void callstack_module_release(struct callstack_module *module) {
  for (size_t i = 0; i < module->row_count; ++i)
    callstack_row_release(module->rows + i);
  free(module->rows);
  free(module->functions);
  if (module->handle)
    dlclose(module->handle);
  free(module);
}

static int callstack_function_compare(const void *left, const void *right) {
  const struct callstack_function *a = left, *b = right;
  if (a->start != b->start)
    return a->start < b->start ? -1 : 1;
  return (a->end > b->end) - (a->end < b->end);
}

static int callstack_row_compare(const void *left, const void *right) {
  const struct callstack_row *a = left, *b = right;
  if (a->start != b->start)
    return a->start < b->start ? -1 : 1;
  return (a->end > b->end) - (a->end < b->end);
}

/* Addresses here are ELF virtual addresses, before the load bias is added. */
static uintptr_t callstack_code_end(const struct dl_phdr_info *info,
                                    uintptr_t address) {
  for (size_t i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr) *phdr = info->dlpi_phdr + i;
    if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X) &&
        address >= phdr->p_vaddr && address - phdr->p_vaddr < phdr->p_memsz)
      return phdr->p_vaddr + phdr->p_memsz;
  }
  return 0;
}

static int callstack_expression_copy(struct callstack_expression *expression,
                                     const Dwarf_Op *ops, size_t count) {
  if (count > callstack_max_expression_ops)
    return ENOTSUP;
  /* These operations carry references into libdw-owned blocks or DIEs. */
  for (size_t i = 0; i < count; ++i) {
    switch (ops[i].atom) {
    case DW_OP_implicit_value:
    case DW_OP_implicit_pointer:
    case DW_OP_entry_value:
    case DW_OP_const_type:
    case DW_OP_regval_type:
    case DW_OP_deref_type:
    case DW_OP_xderef_type:
    case DW_OP_convert:
    case DW_OP_reinterpret:
    case DW_OP_call2:
    case DW_OP_call4:
    case DW_OP_call_ref:
    case DW_OP_GNU_implicit_pointer:
    case DW_OP_GNU_entry_value:
    case DW_OP_GNU_const_type:
    case DW_OP_GNU_regval_type:
    case DW_OP_GNU_deref_type:
    case DW_OP_GNU_convert:
    case DW_OP_GNU_reinterpret:
      return ENOTSUP;
    default:
      break;
    }
  }
  if (count) {
    expression->ops = malloc(count * sizeof(*ops));
    if (!expression->ops)
      return ENOMEM;
    memcpy(expression->ops, ops, count * sizeof(*ops));
  }
  expression->count = count;
  return 0;
}

/* Reject a replaced pathname before trusting its unwind metadata. */
static int callstack_file_matches(const struct dl_phdr_info *info,
                                  const struct stat *file) {
  uintptr_t address = 0;
  uint64_t file_offset = 0;
  for (size_t i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr) *phdr = info->dlpi_phdr + i;
    if (phdr->p_type == PT_LOAD && phdr->p_filesz) {
      address = info->dlpi_addr + phdr->p_vaddr;
      file_offset = phdr->p_offset;
      break;
    }
  }
  if (!address)
    return ENOEXEC;
  FILE *maps = fopen("/proc/self/maps", "re");
  if (!maps)
    return errno;
  char *line = NULL;
  size_t capacity = 0;
  int err = ENOENT;
  while (getline(&line, &capacity, maps) >= 0) {
    unsigned long start, end, offset, inode;
    unsigned device_major, device_minor;
    if (sscanf(line, "%lx-%lx %*4s %lx %x:%x %lu", &start, &end, &offset,
               &device_major, &device_minor, &inode) != 6 ||
        address < start || address >= end)
      continue;
    err = inode == file->st_ino && device_major == major(file->st_dev) &&
                  device_minor == minor(file->st_dev) &&
                  address - start <= UINT64_MAX - offset &&
                  offset + address - start == file_offset
              ? 0
              : ESTALE;
    break;
  }
  if (ferror(maps))
    err = errno ? errno : EIO;
  free(line);
  fclose(maps);
  return err;
}

/* Decode the bounded, non-indirect encodings used by .eh_frame_hdr. */
static int callstack_decode(const unsigned char *data, size_t size,
                            size_t *offset, unsigned encoding, uintptr_t base,
                            uintptr_t *value) {
  if (encoding == DW_EH_PE_omit || (encoding & DW_EH_PE_indirect))
    return ENOTSUP;
  const size_t start = *offset;
  uint64_t raw = 0;
  bool negative = false;
  const unsigned format = encoding & 0x0f;
  if (format == DW_EH_PE_uleb128 || format == DW_EH_PE_sleb128) {
    unsigned shift = 0;
    unsigned byte;
    do {
      if (*offset >= size || shift >= 70)
        return ENOEXEC;
      byte = data[(*offset)++];
      if (shift == 63) {
        const unsigned last = byte & 0x7f;
        if ((format == DW_EH_PE_uleb128 && last > 1) ||
            (format == DW_EH_PE_sleb128 && last != 0 && last != 0x7f))
          return ENOEXEC;
      }
      raw |= (uint64_t)(byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    negative = format == DW_EH_PE_sleb128 && (byte & 0x40);
    if (negative && shift < 64)
      raw |= UINT64_MAX << shift;
  } else {
    size_t bytes;
    switch (format) {
    case DW_EH_PE_absptr:
    case DW_EH_PE_signed:
    case DW_EH_PE_udata8:
    case DW_EH_PE_sdata8:
      bytes = 8;
      break;
    case DW_EH_PE_udata4:
    case DW_EH_PE_sdata4:
      bytes = 4;
      break;
    case DW_EH_PE_udata2:
    case DW_EH_PE_sdata2:
      bytes = 2;
      break;
    default:
      return ENOTSUP;
    }
    if (*offset > size || bytes > size - *offset)
      return ENOEXEC;
    memcpy(&raw, data + *offset, bytes);
    *offset += bytes;
    negative = (format & 8) && (raw & (UINT64_C(1) << (bytes * 8 - 1)));
    if (negative && bytes < 8)
      raw |= UINT64_MAX << (bytes * 8);
  }
  uintptr_t relative;
  switch (encoding & 0x70) {
  case 0:
    relative = 0;
    break;
  case DW_EH_PE_pcrel:
    if (base > UINTPTR_MAX - start)
      return ENOEXEC;
    relative = base + start;
    break;
  case DW_EH_PE_datarel:
    relative = base;
    break;
  default:
    return ENOTSUP;
  }
  if (negative) {
    const uint64_t magnitude = ~raw + 1;
    if (magnitude > relative)
      return ENOEXEC;
    *value = relative - magnitude;
  } else {
    if (raw > UINTPTR_MAX - relative)
      return ENOEXEC;
    *value = relative + raw;
  }
  return 0;
}

static int callstack_copy_rows(struct callstack_module *module, Elf *elf,
                               const struct dl_phdr_info *info,
                               const GElf_Shdr *header,
                               const GElf_Shdr *frames) {
  if (!header->sh_size || !frames->sh_size)
    return 0;
  Elf_Data *data =
      elf_getdata_rawchunk(elf, header->sh_offset, header->sh_size, ELF_T_BYTE);
  if (!data || data->d_size < 4)
    return ENOEXEC;
  const unsigned char *bytes = data->d_buf;
  if (bytes[0] != 1)
    return 0;
  size_t offset = 4;
  uintptr_t frame_address, count;
  int err = callstack_decode(bytes, data->d_size, &offset, bytes[1],
                             header->sh_addr, &frame_address);
  if (!err)
    err = callstack_decode(bytes, data->d_size, &offset, bytes[2],
                           header->sh_addr, &count);
  if (err)
    return err == ENOTSUP ? 0 : err;
  if (frame_address != frames->sh_addr ||
      frames->sh_addr > UINTPTR_MAX - frames->sh_size ||
      count > (data->d_size - offset) / 2 ||
      count > SIZE_MAX / sizeof(uintptr_t))
    return ENOEXEC;
  uintptr_t *starts = malloc(count * sizeof(*starts));
  if (count && !starts)
    return ENOMEM;
  for (size_t i = 0; i < count; ++i) {
    uintptr_t fde;
    err = callstack_decode(bytes, data->d_size, &offset, bytes[3],
                           header->sh_addr, starts + i);
    if (!err)
      err = callstack_decode(bytes, data->d_size, &offset, bytes[3],
                             header->sh_addr, &fde);
    if (err)
      break;
    if (fde < frames->sh_addr || fde >= frames->sh_addr + frames->sh_size ||
        (i && starts[i] < starts[i - 1])) {
      err = ENOEXEC;
      break;
    }
  }
  if (err) {
    free(starts);
    return err == ENOTSUP ? 0 : err;
  }
  errno = 0;
  Dwarf_CFI *cfi = dwarf_getcfi_elf(elf);
  if (!cfi) {
    free(starts);
    return errno == ENOMEM ? ENOMEM : 0;
  }
  size_t capacity = 0;
  for (size_t i = 0; i < count && !err; ++i) {
    uintptr_t address = starts[i];
    uintptr_t limit = callstack_code_end(info, address);
    if (i + 1 < count && starts[i + 1] < limit)
      limit = starts[i + 1];
    while (address < limit) {
      Dwarf_Frame *frame = NULL;
      errno = 0;
      if (dwarf_cfi_addrframe(cfi, address, &frame)) {
        if (errno == ENOMEM)
          err = ENOMEM;
        break;
      }
      struct callstack_row row = {0};
      Dwarf_Addr start, end;
      const int reg = dwarf_frame_info(frame, &start, &end, &row.signal);
      if (reg < 0 || start > address || end <= address ||
          end > UINTPTR_MAX - module->bias) {
        free(frame);
        err = ENOEXEC;
        break;
      }
      row.start = address + module->bias;
      row.end = (end < limit ? end : limit) + module->bias;
      row.return_register = reg;
      Dwarf_Op *ops;
      size_t nops;
      int row_error = 0;
      if (dwarf_frame_cfa(frame, &ops, &nops))
        row_error = ENOTSUP;
      else
        row_error = callstack_expression_copy(&row.cfa, ops, nops);
      for (size_t r = 0; r < CALLSTACK_REGISTERS && !row_error; ++r) {
        Dwarf_Op memory[3];
        if (dwarf_frame_register(frame, r, memory, &ops, &nops)) {
          row_error = ENOTSUP;
          break;
        }
        if (!nops)
          row.registers[r].kind = ops ? CALLSTACK_UNDEFINED : CALLSTACK_SAME;
        else {
          row.registers[r].kind = CALLSTACK_EXPRESSION;
          row_error = callstack_expression_copy(&row.registers[r].expression,
                                                ops, nops);
        }
      }
      free(frame);
      address = row.end - module->bias;
      if (row_error) {
        callstack_row_release(&row);
        if (row_error != ENOTSUP)
          err = row_error;
        continue;
      }
      if (module->row_count == capacity) {
        const size_t next = capacity ? capacity * 2 : 256;
        if (next < capacity || next > SIZE_MAX / sizeof(*module->rows))
          err = EOVERFLOW;
        else {
          void *grown = realloc(module->rows, next * sizeof(*module->rows));
          if (!grown)
            err = ENOMEM;
          else {
            module->rows = grown;
            capacity = next;
          }
        }
      }
      if (err) {
        callstack_row_release(&row);
        break;
      }
      module->rows[module->row_count++] = row;
    }
  }
  dwarf_cfi_end(cfi);
  free(starts);
  if (!err && module->row_count)
    qsort(module->rows, module->row_count, sizeof(*module->rows),
          callstack_row_compare);
  return err;
}

static int callstack_prepare_module(struct dl_phdr_info *info, size_t size,
                                    void *argument) {
  (void)size;
  struct callstack_preparation *preparation = argument;
  for (const struct callstack_module *m = preparation->existing; m; m = m->next)
    if (m->identity == info->dlpi_phdr && m->bias == info->dlpi_addr)
      return 0;

  struct callstack_module *module = calloc(1, sizeof(*module));
  if (!module) {
    preparation->error = ENOMEM;
    return 1;
  }
  module->start = UINTPTR_MAX;
  module->bias = info->dlpi_addr;
  module->identity = info->dlpi_phdr;
  int err = 0, fd = -1;
  Elf *elf = NULL;
  for (size_t i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr) *phdr = info->dlpi_phdr + i;
    if (phdr->p_type != PT_LOAD)
      continue;
    if (phdr->p_vaddr > UINTPTR_MAX - module->bias ||
        phdr->p_memsz > UINTPTR_MAX - module->bias - phdr->p_vaddr) {
      err = ENOEXEC;
      goto done;
    }
    const uintptr_t start = module->bias + phdr->p_vaddr;
    if (start < module->start)
      module->start = start;
    if (start + phdr->p_memsz > module->end)
      module->end = start + phdr->p_memsz;
  }
  if (module->start >= module->end) {
    err = ENOEXEC;
    goto done;
  }
  size_t file_size;
  if (module->bias == getauxval(AT_SYSINFO_EHDR)) {
    /* The kernel retains this mapping, but its in-memory image need not contain
     * the ELF section tables. A vDSO frame therefore remains unknown. */
    goto done;
  } else {
    const bool main_program = !info->dlpi_name || !info->dlpi_name[0];
    module->handle = dlopen(main_program ? NULL : info->dlpi_name,
                            RTLD_LAZY | (main_program ? 0 : RTLD_NOLOAD));
    if (!module->handle) {
      err = ENOENT;
      goto done;
    }
    fd = open(main_program ? "/proc/self/exe" : info->dlpi_name,
              O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      err = errno;
      goto done;
    }
    struct stat status;
    if (fstat(fd, &status)) {
      err = errno;
      goto done;
    }
    err = callstack_file_matches(info, &status);
    if (err)
      goto done;
    if (status.st_size < 0 || (uintmax_t)status.st_size > SIZE_MAX) {
      err = ENOEXEC;
      goto done;
    }
    file_size = status.st_size;
    elf = elf_begin(fd, ELF_C_READ, NULL);
  }
  GElf_Ehdr ehdr;
  if (!elf || !gelf_getehdr(elf, &ehdr) ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr.e_ident[EI_DATA] != ELFDATA2LSB || ehdr.e_machine != EM_X86_64 ||
      (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC)) {
    err = ENOEXEC;
    goto done;
  }
  size_t names;
  size_t phnum, shnum;
  if (elf_getphdrnum(elf, &phnum) || phnum != info->dlpi_phnum ||
      elf_getshdrnum(elf, &shnum) || elf_getshdrstrndx(elf, &names) ||
      (shnum &&
       (ehdr.e_shentsize != sizeof(Elf64_Shdr) || ehdr.e_shoff > file_size ||
        shnum > (file_size - ehdr.e_shoff) / sizeof(Elf64_Shdr)))) {
    err = ENOEXEC;
    goto done;
  }
  for (size_t i = 0; i < phnum; ++i) {
    GElf_Phdr phdr;
    if (!gelf_getphdr(elf, i, &phdr) ||
        memcmp(&phdr, info->dlpi_phdr + i, sizeof(phdr))) {
      err = ESTALE;
      goto done;
    }
  }
  GElf_Shdr header = {0}, frames = {0};
  size_t function_capacity = 0;
  Elf_Scn *section = NULL;
  while ((section = elf_nextscn(elf, section))) {
    GElf_Shdr shdr;
    if (!gelf_getshdr(section, &shdr) ||
        (shdr.sh_type != SHT_NOBITS &&
         (shdr.sh_offset > file_size ||
          shdr.sh_size > file_size - shdr.sh_offset))) {
      err = ENOEXEC;
      goto done;
    }
    const char *name = elf_strptr(elf, names, shdr.sh_name);
    if (!name) {
      err = ENOEXEC;
      goto done;
    }
    if (!strcmp(name, ".eh_frame_hdr"))
      header = shdr;
    else if (!strcmp(name, ".eh_frame"))
      frames = shdr;
    if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
      continue;
    if (shdr.sh_entsize != sizeof(Elf64_Sym) ||
        shdr.sh_size % shdr.sh_entsize) {
      err = ENOEXEC;
      goto done;
    }
    Elf_Data *symbols = NULL;
    while ((symbols = elf_getdata(section, symbols))) {
      const size_t count = symbols->d_size / sizeof(Elf64_Sym);
      if (symbols->d_size % sizeof(Elf64_Sym) || count > INT_MAX) {
        err = ENOEXEC;
        goto done;
      }
      for (size_t i = 0; i < count; ++i) {
        GElf_Sym symbol;
        if (!gelf_getsym(symbols, i, &symbol)) {
          err = ENOEXEC;
          goto done;
        }
        const unsigned type = GELF_ST_TYPE(symbol.st_info);
        if (type != STT_FUNC || !symbol.st_size ||
            symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= SHN_LORESERVE)
          continue;
        const uintptr_t end = callstack_code_end(info, symbol.st_value);
        if (!end || symbol.st_size > end - symbol.st_value) {
          err = ENOEXEC;
          goto done;
        }
        if (module->function_count == function_capacity) {
          const size_t next = function_capacity ? function_capacity * 2 : 256;
          if (next < function_capacity ||
              next > SIZE_MAX / sizeof(*module->functions)) {
            err = EOVERFLOW;
            goto done;
          }
          void *grown =
              realloc(module->functions, next * sizeof(*module->functions));
          if (!grown) {
            err = ENOMEM;
            goto done;
          }
          module->functions = grown;
          function_capacity = next;
        }
        module->functions[module->function_count++] =
            (struct callstack_function){module->bias + symbol.st_value,
                                        module->bias + symbol.st_value +
                                            symbol.st_size};
      }
    }
  }
  if (module->function_count) {
    qsort(module->functions, module->function_count, sizeof(*module->functions),
          callstack_function_compare);
    size_t count = 0;
    for (size_t i = 0; i < module->function_count; ++i) {
      if (count &&
          module->functions[count - 1].start == module->functions[i].start) {
        /* Aliases with unequal extents are not a reliable function boundary. */
        if (module->functions[count - 1].end != module->functions[i].end)
          module->functions[count - 1].end = module->functions[count - 1].start;
      } else
        module->functions[count++] = module->functions[i];
    }
    module->function_count = count;
  }
  err = callstack_copy_rows(module, elf, info, &header, &frames);

done:
  if (elf)
    elf_end(elf);
  if (fd >= 0)
    close(fd);
  if (err) {
    callstack_module_release(module);
    preparation->error = err;
    return 1;
  }
  module->next = preparation->pending;
  preparation->pending = module;
  return 0;
}

int overlaysys_callstack_prepare(void) noexcept {
  const int saved_errno = errno;
  if (atomic_load_explicit(&syscall_user_cb_active, memory_order_relaxed) ||
      atomic_load_explicit(&syscall_internal_emulation, memory_order_relaxed)) {
    errno = EDEADLK;
    return -1;
  }
  if (atomic_exchange_explicit(&callstack_prepare_busy, true,
                               memory_order_acq_rel)) {
    errno = EBUSY;
    return -1;
  }
  kernel_sigset_t saved_mask;
  int err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &saved_mask));
  if (err) {
    atomic_store_explicit(&callstack_prepare_busy, false, memory_order_release);
    errno = err;
    return -1;
  }
  atomic_store_explicit(&syscall_internal_emulation, true,
                        memory_order_relaxed);
  struct callstack_preparation preparation = {
      .existing =
          atomic_load_explicit(&callstack_modules, memory_order_acquire)};
  if (elf_version(EV_CURRENT) == EV_NONE)
    err = ENOTSUP;
  else {
    dl_iterate_phdr(callstack_prepare_module, &preparation);
    err = preparation.error;
  }
  if (err) {
    while (preparation.pending) {
      struct callstack_module *module = preparation.pending;
      preparation.pending = module->next;
      callstack_module_release(module);
    }
  } else {
    if (preparation.pending) {
      struct callstack_module *tail = preparation.pending;
      while (tail->next)
        tail = tail->next;
      tail->next = preparation.existing;
      atomic_store_explicit(&callstack_modules, preparation.pending,
                            memory_order_release);
    }
    atomic_store_explicit(&callstack_ready, true, memory_order_release);
  }
  atomic_store_explicit(&syscall_internal_emulation, false,
                        memory_order_relaxed);
  atomic_store_explicit(&callstack_prepare_busy, false, memory_order_release);
  const int restore_err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &saved_mask, NULL));
  if (!err)
    err = restore_err;
  errno = err ? err : saved_errno;
  return err ? -1 : 0;
}
