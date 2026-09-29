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

/*
 * Explicit object selection and irreversible patch ownership. A loaded object
 * enters the registry before preparation; only complete objects satisfy status
 * queries. Failed preparation can be rebuilt, while written text retains every
 * resource it references and retries only its remaining protection step.
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <glob.h>
#include <link.h>
#include <unistd.h>

#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <capstone/capstone.h>

#include "patcher.h"
#include "util.h"

#include "x86/intercept.h"

struct patcher_patched_object {
  struct intercept_desc desc;
  const ElfW(Phdr) * prog_headers;
  void *handle;
  unsigned char *wrappers;
  size_t wrappers_size;
  bool needs_cleanup;
  bool prepared;
  bool complete;
  struct patcher_patched_object *pending_next;
  struct patcher_patched_object *next;
};

struct patcher_patch_target {
  const char *name;
  struct stat *files;
  size_t cnt;
  bool wildcard;
  bool matched;
  bool protected_match;
};

struct patcher_protected_objects {
  uintptr_t self;
  uintptr_t capstone;
  uintptr_t vdso;
};

struct patcher_patch_selection {
  struct patcher_patch_target *targets;
  size_t cnt;
  bool exclude;
  bool query;
  bool unpatched;
  bool skip_missing;
  int err;
  struct patcher_protected_objects objects;
  struct patcher_patched_object *pending;
};

static struct patcher_patched_object *patcher_patched_objects;
static struct patcher_patched_object *patcher_unreleased_objects;
static bool patcher_inited;
/* glob has no user-data argument; all patcher entry points are serialized. */
static int patcher_glob_lookup_err;

static int patcher_selection_err(int err) {
  errno = err ? err : EIO;
  return -1;
}

static int patcher_glob_err(const char *path, int err) {
  (void)path;
  if (err == ENOENT || err == ENOTDIR)
    return 0;
  if (!patcher_glob_lookup_err)
    patcher_glob_lookup_err = err;
  return 1;
}

static int patcher_identify_target(const char *path, bool skip_missing,
                                   struct patcher_patch_target *target) {
  *target = (struct patcher_patch_target){0};
  if (path == NULL || path[0] == '\0')
    return patcher_selection_err(EINVAL);
  target->wildcard = strchr(path, '*') != NULL;
  if (strchr(path, '/') == NULL) {
    target->name = path;
    return 0;
  }
  if (!target->wildcard) {
    char *canonical = realpath(path, NULL);
    if (canonical == NULL) {
      if (skip_missing && (errno == ENOENT || errno == ENOTDIR))
        return 0;
      return -1;
    }
    struct stat file;
    int res = stat(canonical, &file);
    int err = res ? errno : 0;
    free(canonical);
    if (res) {
      if (skip_missing && (err == ENOENT || err == ENOTDIR))
        return 0;
      return patcher_selection_err(err);
    }
    if (!S_ISREG(file.st_mode))
      return patcher_selection_err(EINVAL);
    target->files = malloc(sizeof(*target->files));
    if (target->files == NULL)
      return patcher_selection_err(ENOMEM);
    target->files[0] = file;
    target->cnt = 1;
    return 0;
  }

  size_t len = strlen(path);
  if (len > (SIZE_MAX - 1) / 2)
    return patcher_selection_err(EOVERFLOW);
  char *pattern = malloc(len * 2 + 1);
  if (pattern == NULL)
    return patcher_selection_err(ENOMEM);
  char *next = pattern;
  for (const char *part = path; *part != '\0'; ++part) {
    if (*part == '\\' || *part == '?' || *part == '[' || *part == ']')
      *next++ = '\\';
    *next++ = *part;
  }
  *next = '\0';
  glob_t paths = {0};
  patcher_glob_lookup_err = 0;
  int res = glob(pattern, GLOB_NOSORT, patcher_glob_err, &paths);
  int err = patcher_glob_lookup_err;
  free(pattern);
  if (res != 0 && res != GLOB_NOMATCH) {
    if (!err)
      err = res == GLOB_NOSPACE ? ENOMEM : EIO;
    globfree(&paths);
    return patcher_selection_err(err);
  }
  if (paths.gl_pathc > SIZE_MAX / sizeof(*target->files)) {
    globfree(&paths);
    return patcher_selection_err(EOVERFLOW);
  }
  if (paths.gl_pathc != 0) {
    target->files = calloc(paths.gl_pathc, sizeof(*target->files));
    if (target->files == NULL) {
      globfree(&paths);
      return patcher_selection_err(ENOMEM);
    }
    target->cnt = paths.gl_pathc;
    for (size_t i = 0; i < target->cnt; ++i) {
      if (stat(paths.gl_pathv[i], target->files + i) != 0) {
        err = errno;
        if (err != ENOENT && err != ENOTDIR)
          break;
        target->files[i] = (struct stat){0};
        err = 0;
      }
    }
  }
  globfree(&paths);
  return err ? patcher_selection_err(err) : 0;
}

static bool patcher_match_name(const char *pattern, const char *name) {
  const char *star = NULL;
  const char *retry = NULL;
  while (*name != '\0') {
    if (*pattern == '*') {
      star = pattern++;
      retry = name;
    } else if (*pattern == *name) {
      ++pattern;
      ++name;
    } else if (star != NULL) {
      pattern = star + 1;
      name = ++retry;
    } else {
      return false;
    }
  }
  while (*pattern == '*')
    ++pattern;
  return *pattern == '\0';
}

static bool
patcher_object_is_protected(const struct dl_phdr_info *info,
                            const struct patcher_protected_objects *objects,
                            uintptr_t *addr, bool *self) {
  *addr = 0;
  *self = false;
  bool capstone = false;
  for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr) *segment = info->dlpi_phdr + i;
    if (segment->p_type != PT_LOAD)
      continue;
    uintptr_t start = info->dlpi_addr + segment->p_vaddr;
    if (*addr == 0 && segment->p_filesz != 0)
      *addr = start;
    *self |= objects->self >= start && objects->self - start < segment->p_memsz;
    capstone |= objects->capstone >= start &&
                objects->capstone - start < segment->p_memsz;
  }
  return (objects->vdso != 0 && *addr == objects->vdso) || *addr == 0 ||
         info->dlpi_name == NULL || info->dlpi_name[0] == '\0' || *self ||
         capstone;
}

/* Returning normally from this callback releases the dynamic loader's lock. */
static int patcher_inspect_object(struct dl_phdr_info *info,
                                  struct patcher_patch_selection *selection) {
  uintptr_t addr;
  bool self;
  bool protected_object =
      patcher_object_is_protected(info, &selection->objects, &addr, &self);
  bool vdso = selection->objects.vdso != 0 && addr == selection->objects.vdso;
  uintptr_t start = 0, end = 0;
  dev_t dev = 0;
  ino_t inode = 0;
  if (!vdso && addr != 0) {
    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps == NULL)
      return -1;
    char *line = NULL;
    size_t capacity = 0;
    unsigned major_num = 0, minor_num = 0;
    unsigned long inode_num = 0;
    bool mapped = false;
    int err = 0;
    errno = 0;
    while (getline(&line, &capacity, maps) >= 0) {
      if (sscanf(line, "%lx-%lx %*s %*x %x:%x %lu", &start, &end, &major_num,
                 &minor_num, &inode_num) != 5) {
        err = EIO;
        break;
      }
      if (start <= addr && addr < end) {
        mapped = true;
        break;
      }
    }
    if (!err && ferror(maps))
      err = errno ? errno : EIO;
    if (!err && !mapped)
      err = errno ? errno : ESTALE;
    free(line);
    if (fclose(maps) != 0 && !err)
      err = errno ? errno : EIO;
    if (err)
      return patcher_selection_err(err);
    dev = makedev(major_num, minor_num);
    inode = (ino_t)inode_num;
  }

  const char *name = info->dlpi_name != NULL ? info->dlpi_name : "";
  const char *slash = strrchr(name, '/');
  if (slash != NULL)
    name = slash + 1;
  bool selected = false;
  for (size_t i = 0; i < selection->cnt; ++i) {
    struct patcher_patch_target *target = selection->targets + i;
    bool matches =
        target->name != NULL && patcher_match_name(target->name, name);
    for (size_t j = 0; !matches && j < target->cnt; ++j) {
      const struct stat *file = target->files + j;
      matches = S_ISREG(file->st_mode) && file->st_dev == dev &&
                file->st_ino == inode;
    }
    if (!matches)
      continue;
    selected = true;
    if (protected_object && !selection->exclude) {
      target->protected_match = true;
      if (!selection->query && (self || !target->wildcard))
        return patcher_selection_err(EPERM);
    } else {
      target->matched = true;
    }
  }
  if (protected_object || (selection->exclude ? selected : !selected))
    return 0;

  struct patcher_patched_object *object;
  for (object = patcher_patched_objects; object != NULL;
       object = object->next) {
    if (object->prog_headers == info->dlpi_phdr) {
      if (object->desc.base_addr != (unsigned char *)info->dlpi_addr ||
          object->desc.dev != dev || object->desc.inode != inode)
        return patcher_selection_err(ESTALE);
      break;
    }
  }
  if (selection->query) {
    if (object == NULL || !object->complete)
      selection->unpatched = true;
    return 0;
  }
  if (object != NULL) {
    if (!object->complete) {
      object->pending_next = selection->pending;
      selection->pending = object;
    }
    return 0;
  }

  struct intercept_desc desc = {.base_addr = (unsigned char *)info->dlpi_addr,
                                .dev = dev,
                                .inode = inode};
  for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr) *segment = info->dlpi_phdr + i;
    if (segment->p_type != PT_LOAD || !(segment->p_flags & PF_X) ||
        segment->p_filesz == 0)
      continue;
    if (desc.text_start != NULL || !(segment->p_flags & PF_R) ||
        (segment->p_flags & PF_W))
      return patcher_selection_err(EOPNOTSUPP);
    desc.text_start = desc.base_addr + segment->p_vaddr;
    desc.text_end = desc.text_start + segment->p_filesz - 1;
  }
  if (desc.text_start == NULL)
    return patcher_selection_err(ENOEXEC);

  char mapping[96];
  int len = snprintf(mapping, sizeof(mapping), "/proc/self/map_files/%lx-%lx",
                     start, end);
  if (len <= 0 || (size_t)len >= sizeof(mapping))
    return patcher_selection_err(EOVERFLOW);
  char path[PATH_MAX + 1];
  ssize_t path_size = readlink(mapping, path, sizeof(path) - 1);
  if (path_size < 0)
    return -1;
  if (path_size == 0 || (size_t)path_size >= sizeof(path) - 1)
    return patcher_selection_err(ENAMETOOLONG);
  path[path_size] = '\0';
  char *canonical = realpath(path, NULL);
  if (canonical == NULL)
    return -1;
  struct stat file;
  if (stat(canonical, &file) != 0) {
    int err = errno;
    free(canonical);
    return patcher_selection_err(err);
  }
  if (!S_ISREG(file.st_mode) || file.st_dev != dev || file.st_ino != inode) {
    free(canonical);
    return patcher_selection_err(ESTALE);
  }
  object = calloc(1, sizeof(*object));
  if (object == NULL) {
    free(canonical);
    return patcher_selection_err(ENOMEM);
  }
  object->desc.path = canonical;
  void *handle = dlopen(info->dlpi_name, RTLD_NOW | RTLD_NOLOAD);
  if (handle == NULL)
    handle = dlopen(canonical, RTLD_NOW | RTLD_NOLOAD);
  if (handle == NULL) {
    free(canonical);
    free(object);
    return patcher_selection_err(EIO);
  }
  object->handle = handle;
  int err = 0;
  struct link_map *loaded = NULL;
  if (dlinfo(handle, RTLD_DI_LINKMAP, &loaded) != 0 || loaded == NULL) {
    err = EIO;
  } else if (loaded->l_addr != info->dlpi_addr) {
    err = ESTALE;
  } else {
    Dl_info image;
    void *owner = NULL;
    if (dladdr1((void *)addr, &image, &owner, RTLD_DL_LINKMAP) == 0 ||
        owner != (void *)loaded)
      err = ESTALE;
  }
  if (err) {
    /* A failed reference release remains owned and is retried on a patch call.
     * Do not register an object before its identity has been verified. */
    if (dlclose(handle) != 0) {
      object->next = patcher_unreleased_objects;
      patcher_unreleased_objects = object;
    } else {
      free(canonical);
      free(object);
    }
    return patcher_selection_err(err);
  }
  desc.path = canonical;
  object->desc = desc;
  object->prog_headers = info->dlpi_phdr;
  object->next = patcher_patched_objects;
  patcher_patched_objects = object;
  object->pending_next = selection->pending;
  selection->pending = object;
  return 0;
}

static int patcher_select_object(struct dl_phdr_info *info, size_t size,
                                 void *opaque) {
  (void)size;
  struct patcher_patch_selection *selection = opaque;
  if (patcher_inspect_object(info, selection) == 0)
    return 0;
  selection->err = errno ? errno : EIO;
  return 1;
}

static int patcher_inspect_objects(struct patcher_patch_selection *selection) {
  selection->objects = (struct patcher_protected_objects){
      .self = (uintptr_t)patcher_patch_all,
      .capstone = (uintptr_t)cs_open,
      .vdso = (uintptr_t)getauxval(AT_SYSINFO_EHDR)};
  int res = dl_iterate_phdr(patcher_select_object, selection);
  if (selection->err)
    return patcher_selection_err(selection->err);
  return res == 0 ? 0 : patcher_selection_err(EIO);
}

/* Only preparation resources are released. Written patches retain all owners.
 */
static int patcher_clear_preparation(struct patcher_patched_object *object) {
  if (object->desc.text_written)
    return patcher_selection_err(EBUSY);
  int err = 0;
  if (intercept_desc_release(&object->desc) != 0)
    err = errno ? errno : EIO;
  if (object->wrappers != NULL) {
    if (util_xmunmap(object->wrappers, object->wrappers_size) == 0) {
      object->wrappers = NULL;
      object->wrappers_size = 0;
    } else if (!err) {
      err = errno ? errno : EIO;
    }
  }
  if (err)
    return patcher_selection_err(err);
  object->needs_cleanup = false;
  object->prepared = false;
  return 0;
}

static int patcher_prepare_object(struct patcher_patched_object *object) {
  if (object->prepared)
    return 0;
  if (object->needs_cleanup && patcher_clear_preparation(object) != 0)
    return -1;
  object->needs_cleanup = true;
  struct intercept_desc *desc = &object->desc;
  if (intercept_desc_find_syscalls(desc) != 0)
    goto failure;
  if (desc->cnt != 0) {
    if (patcher_asm_wrapper_tmpl_size > SIZE_MAX - 3 * 15 - 14) {
      errno = EOVERFLOW;
      goto failure;
    }
    size_t per_wrapper = patcher_asm_wrapper_tmpl_size + 3 * 15 + 14;
    if (desc->cnt > (SIZE_MAX - PAGE_SIZE + 1) / per_wrapper) {
      errno = EOVERFLOW;
      goto failure;
    }
    object->wrappers_size =
        (desc->cnt * per_wrapper + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    object->wrappers = util_xmmap_anon(object->wrappers_size);
    if (object->wrappers == NULL)
      goto failure;
    unsigned char *next = object->wrappers;
    if (intercept_desc_alloc_trampoline_table(desc) != 0 ||
        patcher_create_patch_wrappers(desc, &next) != 0)
      goto failure;
    if ((size_t)(next - object->wrappers) > object->wrappers_size) {
      errno = EOVERFLOW;
      goto failure;
    }
    if (util_mprotect_no_intercept(object->wrappers, object->wrappers_size,
                                   PROT_READ | PROT_EXEC) != 0 ||
        patcher_prepare_trampolines(desc) != 0)
      goto failure;
  }
  object->prepared = true;
  object->needs_cleanup = false;
  return 0;

failure: {
  int err = errno ? errno : EIO;
  patcher_clear_preparation(object);
  return patcher_selection_err(err);
}
}

static int patcher_patch_selected(struct patcher_patch_selection *selection) {
  while (patcher_unreleased_objects != NULL) {
    struct patcher_patched_object *object = patcher_unreleased_objects;
    if (dlclose(object->handle) != 0)
      return patcher_selection_err(EIO);
    patcher_unreleased_objects = object->next;
    free((void *)object->desc.path);
    free(object);
  }
  if (!patcher_inited) {
    errno = 0;
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0)
      return patcher_selection_err(errno);
    if (page_size != (long)PAGE_SIZE)
      return patcher_selection_err(EOPNOTSUPP);
    if (patcher_init() != 0)
      return -1;
    patcher_inited = true;
  }
  if (patcher_inspect_objects(selection) != 0)
    return -1;
  for (size_t i = 0; i < selection->cnt; ++i) {
    const struct patcher_patch_target *target = selection->targets + i;
    if (!selection->exclude && target->protected_match && !target->matched)
      return patcher_selection_err(EPERM);
    if (!selection->skip_missing && !target->matched)
      return patcher_selection_err(ENOENT);
  }
  for (struct patcher_patched_object *object = selection->pending;
       object != NULL; object = object->pending_next) {
    if (patcher_prepare_object(object) != 0)
      return -1;
  }
  for (struct patcher_patched_object *object = selection->pending;
       object != NULL; object = object->pending_next) {
    if (patcher_activate_patches(&object->desc) != 0)
      return -1;
    object->complete = true;
  }
  return 0;
}

static int patcher_patch_objects(size_t len, const char *const *paths,
                                 bool skip_missing, bool exclude) {
  if (len != 0 && paths == NULL)
    return patcher_selection_err(EINVAL);
  if (len > SIZE_MAX / sizeof(struct patcher_patch_target))
    return patcher_selection_err(EOVERFLOW);
  struct patcher_patch_selection selection = {
      .cnt = len, .exclude = exclude, .skip_missing = skip_missing};
  if (len != 0) {
    selection.targets = calloc(len, sizeof(*selection.targets));
    if (selection.targets == NULL)
      return patcher_selection_err(ENOMEM);
    for (size_t i = 0; i < len; ++i) {
      if (patcher_identify_target(paths[i], skip_missing,
                                  selection.targets + i) != 0) {
        selection.err = errno ? errno : EIO;
        break;
      }
    }
  }
  int res = selection.err ? patcher_selection_err(selection.err)
                          : patcher_patch_selected(&selection);
  int err = res ? (errno ? errno : EIO) : 0;
  for (size_t i = 0; i < len; ++i)
    free(selection.targets[i].files);
  free(selection.targets);
  return err ? patcher_selection_err(err) : 0;
}

int patcher_patch(size_t len, const char *const *paths, bool skip_missing) {
  return patcher_patch_objects(len, paths, skip_missing, false);
}

int patcher_patch_all(size_t len, const char *const *inhibit_patch) {
  return patcher_patch_objects(len, inhibit_patch, true, true);
}

int patcher_patch_check(const char *path, bool *patched) {
  if (patched == NULL)
    return patcher_selection_err(EINVAL);
  struct patcher_patch_target target;
  if (patcher_identify_target(path != NULL ? path : "*", true, &target) != 0) {
    int err = errno ? errno : EIO;
    free(target.files);
    return patcher_selection_err(err);
  }
  struct patcher_patch_selection selection = {
      .targets = &target, .cnt = 1, .query = true};
  int res = patcher_inspect_objects(&selection);
  int err = res ? (errno ? errno : EIO) : 0;
  if (!res)
    *patched = (path == NULL || target.matched) && !selection.unpatched &&
               (target.wildcard || !target.protected_match);
  free(target.files);
  return err ? patcher_selection_err(err) : 0;
}
