#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <dwarf.h>
#include <elfutils/libdwfl.h>

#include "internal.h"

#include "generated/version.h"

enum { HOOK_KINDS = OVERLAYSYS_HOOK_TYPE_CLONE_PARENT_EPILOGUE + 1 };

struct hook_entry {
  icdlist_t link;
  void *handler;
};

struct hook_data {
  icdlist_t heads[HOOK_KINDS];
  struct hook_entry entries[];
};

/* This fixed anchor and the complete node arena are shared by fork descendants.
 */
struct hook_registry {
  pthread_mutex_t mutex;
  size_t page_size, max, cnt;
  _Atomic size_t lens[HOOK_KINDS];
  _Atomic size_t bytes;
  _Atomic uintptr_t canonical;
};

static struct hook_registry *hook_registry;
static int hook_registry_err = ENODEV;
int hook_backing_fd = -1;

/* Only VMA bookkeeping is process-local. Low bit marks an unfinished remap. */
static _Atomic(struct hook_data *) hook_view;
static _Atomic size_t hook_view_bytes;
static _Atomic size_t hook_view_state;

static __attribute__((constructor(101))) void hook_init(void) {
  const int saved_errno = errno;

  log_msg(LOG_DEBUG,
          "liboverlaysys (version %s) by Jihong Min "
          "(hurryman2212@gmail.com)",
          version);

  const long page = sysconf(_SC_PAGESIZE);
  struct hook_registry *ctl = MAP_FAILED;
  struct hook_data *data = MAP_FAILED;
  int fd = -1, err = EINVAL;
  if (page <= 0 || !has_single_bit((unsigned long)page) ||
      (size_t)page < sizeof(*ctl) || (size_t)page < sizeof(*data))
    goto done;

  struct rlimit limit;
  const long res = util_syscall_no_intercept(
      SYS_prlimit64, 0L, (long)RLIMIT_FSIZE, 0L, (long)&limit, 0L, 0L);
  if (res < 0) {
    err = -res;
    goto done;
  }
  size_t max = (size_t)PTRDIFF_MAX;
  if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < max)
    max = limit.rlim_cur;
  max &= ~((size_t)page - 1);
  if (max < (size_t)page) {
    err = EFBIG;
    goto done;
  }

  ctl = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1,
             0);
  if (ctl == MAP_FAILED) {
    err = errno;
    goto done;
  }
  fd = memfd_create("overlaysys-hooks", MFD_CLOEXEC);
  if (fd < 0 || ftruncate(fd, (off_t)page)) {
    err = errno;
    goto done;
  }
  /* CRIU maps the entire backing file, so size it only for live storage. */
  data = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (data == MAP_FAILED) {
    err = errno;
    goto done;
  }
  pthread_mutexattr_t attrs;
  err = pthread_mutexattr_init(&attrs);
  if (err)
    goto done;
  err = pthread_mutexattr_setpshared(&attrs, PTHREAD_PROCESS_SHARED);
  if (!err)
    err = pthread_mutex_init(&ctl->mutex, &attrs);
  pthread_mutexattr_destroy(&attrs);
  if (err)
    goto done;

  for (size_t i = 0; i < HOOK_KINDS; ++i)
    icdlist_init(&data->heads[i]);
  ctl->page_size = page;
  ctl->max = max;
  atomic_store_explicit(&ctl->bytes, page, memory_order_relaxed);
  atomic_store_explicit(&ctl->canonical, (uintptr_t)data, memory_order_relaxed);
  hook_view = data;
  hook_view_bytes = page;
  atomic_store_explicit(&hook_view_state, page, memory_order_release);
  hook_registry = ctl;
  hook_backing_fd = fd;
  fd = -1;

done:
  /* Successful initialization retains a CLOEXEC FD for unprivileged growth.
   * Intercepted FD operations protect it in each descendant's FD table. */
  if (fd >= 0)
    util_syscall_no_intercept(SYS_close, (long)fd, 0L, 0L, 0L, 0L, 0L);
  if (err) {
    if (data != MAP_FAILED)
      munmap(data, page);
    if (ctl != MAP_FAILED)
      munmap(ctl, page);
  }
  hook_registry_err = err;

  errno = saved_errno;
}

int hook_resize_backing(int fd, size_t bytes) {
  struct stat st;
  int err = patcher_syscall_err_code(util_syscall_no_intercept(
      SYS_fstat, (long)fd, (long)&st, 0L, 0L, 0L, 0L));
  if (err)
    return err;
  /* A pre-interception close/dup2 may have reused this number. Compare with
   * the current VMA, not a cached inode: CRIU recreates the backing inode.
   * Reopen maps on each resize so replacing the proc mount is harmless. */
  FILE *const maps = fopen("/proc/self/maps", "re");
  if (!maps)
    return errno;
  char *line = NULL;
  size_t capacity = 0;
  err = ESTALE;
  for (;;) {
    errno = 0;
    if (getline(&line, &capacity, maps) < 0) {
      if (!feof(maps))
        err = errno ? errno : EIO;
      break;
    }
    unsigned long start, end, offset, inode;
    unsigned int dev_major, dev_minor;
    if (sscanf(line, "%lx-%lx %*s %lx %x:%x %lu", &start, &end, &offset,
               &dev_major, &dev_minor, &inode) != 6 ||
        start != (uintptr_t)hook_view || end - start != hook_view_bytes)
      continue;
    if (!offset && inode && inode == st.st_ino &&
        makedev(dev_major, dev_minor) == st.st_dev)
      err = 0;
    break;
  }
  free(line);
  if (fclose(maps) && !err)
    err = errno;
  if (!err)
    err = patcher_syscall_err_code(util_syscall_no_intercept(
        SYS_ftruncate, (long)fd, (long)bytes, 0L, 0L, 0L, 0L));
  return err;
}

/*
 * All processes quiesce dispatch while registrations change. Afterward, a
 * stale view cannot be read until this process publishes its new size. Block
 * signals before claiming refresh ownership, so a nested hook cannot wait on
 * its interrupted thread. Publication also releases ownership in one store.
 */
static int hook_resize_view(size_t bytes, bool reclaim) {
  if (!reclaim &&
      atomic_load_explicit(&hook_view_state, memory_order_acquire) == bytes)
    return 0;
  kernel_sigset_t mask;
  int err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &mask));
  if (err)
    return err;
  const bool internal = atomic_exchange_explicit(&syscall_internal_emulation,
                                                 true, memory_order_relaxed);
  size_t state;
  for (;;) {
    state = atomic_load_explicit(&hook_view_state, memory_order_acquire);
    if (state & 1) {
      x86_pause();
      continue;
    }
    if (!reclaim && state == bytes)
      goto done;
    if (atomic_compare_exchange_weak_explicit(&hook_view_state, &state,
                                              state | 1, memory_order_acquire,
                                              memory_order_relaxed))
      break;
  }

  const size_t old_bytes = hook_view_bytes;
  if (bytes >
          atomic_load_explicit(&hook_registry->bytes, memory_order_relaxed) ||
      (reclaim && bytes < old_bytes)) {
    /* Writers alone resize the inode shared by all fork descendants. The FD
     * table lock keeps dup2/dup3 relocation from racing this ftruncate. */
    err = syscall_resize_hook_backing(bytes);
    if (err && !reclaim)
      goto publish;
    /* Removal remains committed when backing reclamation is denied. */
    err = 0;
  }
  if (reclaim && bytes < old_bytes)
    util_syscall_no_intercept(SYS_madvise, (long)((char *)hook_view + bytes),
                              (long)(old_bytes - bytes), (long)MADV_REMOVE, 0L,
                              0L, 0L);
  if (bytes != old_bytes) {
    const long res = util_syscall_no_intercept(
        SYS_mremap, (long)hook_view, (long)old_bytes, (long)bytes,
        bytes > old_bytes ? (long)MREMAP_MAYMOVE : 0L, 0L, 0L);
    err = patcher_syscall_err_code(res);
    if (!err) {
      hook_view = (void *)res;
      hook_view_bytes = bytes;
    } else if (bytes < old_bytes) {
      /* The old VMA still covers every live node; reclamation is best effort.
       */
      err = 0;
    }
  }
publish:
  atomic_store_explicit(&hook_view_state, err ? state : bytes,
                        memory_order_release);

done:
  atomic_store_explicit(&syscall_internal_emulation, internal,
                        memory_order_relaxed);
  const int restore_err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &mask, NULL));
  /* A failed mask restoration is never a harmless oversized-view fallback. */
  log_verify(!restore_err);
  return err;
}

/* Shared links use the last writer's base; callback code pointers do not move.
 */
static icdlist_t *hook_link(icdlist_t *link, uintptr_t delta) {
  return (icdlist_t *)((uintptr_t)link + delta);
}

static void hook_rebase(void) {
  struct hook_data *const data =
      atomic_load_explicit(&hook_view, memory_order_relaxed);
  const uintptr_t delta =
      (uintptr_t)data -
      atomic_load_explicit(&hook_registry->canonical, memory_order_relaxed);
  if (!delta)
    return;
  for (size_t i = 0; i < HOOK_KINDS; ++i) {
    data->heads[i].prev = hook_link(data->heads[i].prev, delta);
    data->heads[i].next = hook_link(data->heads[i].next, delta);
  }
  for (size_t i = 0; i < hook_registry->cnt; ++i) {
    data->entries[i].link.prev = hook_link(data->entries[i].link.prev, delta);
    data->entries[i].link.next = hook_link(data->entries[i].link.next, delta);
  }
  atomic_store_explicit(&hook_registry->canonical, (uintptr_t)data,
                        memory_order_release);
}

static struct hook_data *hook_read(void) {
  if (!hook_registry)
    return NULL;
  const size_t bytes =
      atomic_load_explicit(&hook_registry->bytes, memory_order_acquire);
  /* Never silently omit registered hooks when this process cannot map them. */
  const int err = hook_resize_view(bytes, false);
  log_verify(!err || atomic_load_explicit(&hook_view_bytes,
                                          memory_order_acquire) >= bytes);
  return hook_view;
}

void hook_prepare_fork(void) {
  /* A private child must not inherit another thread's unfinished remap. */
  if (hook_registry)
    log_verify(!hook_resize_view(
        atomic_load_explicit(&hook_registry->bytes, memory_order_acquire),
        false));
}

static size_t hook_bytes(size_t cnt) {
  return align_val_pow2(sizeof(struct hook_data) +
                            cnt * sizeof(struct hook_entry),
                        hook_registry->page_size);
}

/* Keep the pool dense; repair the moved tail's links before shrinking the VMA.
 */
static void hook_release(struct hook_entry *entry) {
  icdlist_remove(&entry->link);
  struct hook_entry *const last = &hook_view->entries[--hook_registry->cnt];
  if (entry != last) {
    *entry = *last;
    entry->link.prev->next = &entry->link;
    entry->link.next->prev = &entry->link;
  }
}

static void hook_shrink(void) {
  const size_t bytes = hook_bytes(hook_registry->cnt);
  if (bytes <
      atomic_load_explicit(&hook_registry->bytes, memory_order_relaxed)) {
    /* Removal is committed even if shrinking/reclaiming unused pages fails. */
    (void)hook_resize_view(bytes, true);
    hook_rebase();
    atomic_store_explicit(&hook_registry->bytes, bytes, memory_order_release);
  }
}

/* The sentinel denotes insertion at the end, or an absent removal position. */
static icdlist_t *hook_pos(icdlist_t *head, ptrdiff_t idx, uintptr_t delta) {
  if (idx == -1)
    return head;
  icdlist_t *pos = hook_link(head->next, delta);
  while (idx && pos != head) {
    pos = hook_link(pos->next, delta);
    --idx;
  }
  return idx ? NULL : pos;
}

/* The caller holds the registry mutex; readers keep the shared links intact. */
static struct hook_entry *hook_at(overlaysys_hook_type_t type, ptrdiff_t idx) {
  const uintptr_t delta =
      (uintptr_t)hook_view -
      atomic_load_explicit(&hook_registry->canonical, memory_order_relaxed);
  icdlist_t *const head = &hook_view->heads[type];
  icdlist_t *const pos =
      idx == -1 ? hook_link(head->prev, delta) : hook_pos(head, idx, delta);
  return pos && pos != head ? icdlist_entry(pos, struct hook_entry, link)
                            : NULL;
}

/* This detects local misuse, not concurrent dispatch in another thread. */
static bool hook_lock(bool rebase) {
  if (atomic_load_explicit(&syscall_user_cb_active, memory_order_relaxed)) {
    errno = EDEADLK;
    return false;
  }
  if (!hook_registry) {
    errno = hook_registry_err;
    return false;
  }
  /* Lock and allocator syscalls must not reenter user hooks. */
  atomic_store_explicit(&syscall_user_cb_active, true, memory_order_relaxed);
  int err = pthread_mutex_lock(&hook_registry->mutex);
  if (err) {
    atomic_store_explicit(&syscall_user_cb_active, false, memory_order_relaxed);
    errno = err;
    return false;
  }
  err = hook_resize_view(
      atomic_load_explicit(&hook_registry->bytes, memory_order_acquire), false);
  if (err) {
    log_verify(!pthread_mutex_unlock(&hook_registry->mutex));
    atomic_store_explicit(&syscall_user_cb_active, false, memory_order_relaxed);
    errno = err;
    return false;
  }
  /* Readers translate links without changing a concurrent dispatch's base. */
  if (rebase)
    hook_rebase();
  return true;
}

static void hook_unlock(int saved_errno) {
  log_verify(!pthread_mutex_unlock(&hook_registry->mutex));
  atomic_store_explicit(&syscall_user_cb_active, false, memory_order_relaxed);
  errno = saved_errno;
}

ptrdiff_t overlaysys_hook_insert(overlaysys_hook_type_t type,
                                 void *restrict handler, ptrdiff_t idx,
                                 bool replace) noexcept {
  const int saved_errno = errno;
  if ((unsigned)type >= HOOK_KINDS || !handler || idx < -1) {
    errno = EINVAL;
    return -1;
  }
  if (!hook_lock(true))
    return -1;
  const size_t len = hook_registry->lens[type];
  if (idx == -1)
    /* The arena's PTRDIFF_MAX bound also bounds each list's length. */
    idx = (ptrdiff_t)len;
  else if ((size_t)idx > len) {
    hook_unlock(EINVAL);
    return -1;
  }
  icdlist_t *const head = &hook_view->heads[type];
  ptrdiff_t existing_idx = 0;
  for (icdlist_t *node = head->next; node != head;
       node = node->next, ++existing_idx) {
    const struct hook_entry *const entry =
        icdlist_entry(node, struct hook_entry, link);
    if (entry->handler == handler) {
      hook_unlock(saved_errno);
      return existing_idx;
    }
  }
  icdlist_t *pos = (size_t)idx == len ? head : hook_pos(head, idx, 0);

  if (replace && pos != head) {
    struct hook_entry *const entry =
        icdlist_entry(pos, struct hook_entry, link);
    entry->handler = handler;
    hook_unlock(saved_errno);
    return idx;
  }

  if (hook_registry->cnt >= (hook_registry->max - sizeof(struct hook_data)) /
                                sizeof(struct hook_entry)) {
    hook_unlock(ENOMEM);
    return -1;
  }
  const size_t pos_off = (char *)pos - (char *)hook_view;
  const size_t bytes = hook_bytes(hook_registry->cnt + 1);
  const int err = hook_resize_view(bytes, false);
  if (err) {
    hook_unlock(err);
    return -1;
  }
  hook_rebase();
  pos = (void *)((char *)hook_view + pos_off);
  struct hook_entry *const entry = &hook_view->entries[hook_registry->cnt++];
  entry->handler = handler;
  icdlist_insert_before(pos, &entry->link);
  hook_registry->lens[type] = len + 1;
  atomic_store_explicit(&hook_registry->bytes, bytes, memory_order_release);
  hook_unlock(saved_errno);
  return idx;
}

void *overlaysys_hook_get(overlaysys_hook_type_t type, ptrdiff_t idx) noexcept {
  const int saved_errno = errno;
  if ((unsigned)type >= HOOK_KINDS || idx < -1) {
    errno = EINVAL;
    return NULL;
  }
  if (!hook_lock(false))
    return NULL;
  const struct hook_entry *const entry = hook_at(type, idx);
  void *const handler = entry ? entry->handler : NULL;
  hook_unlock(handler ? saved_errno : ENOENT);
  return handler;
}

void *overlaysys_hook_remove(overlaysys_hook_type_t type,
                             ptrdiff_t idx) noexcept {
  const int saved_errno = errno;
  if ((unsigned)type >= HOOK_KINDS || idx < -1) {
    errno = EINVAL;
    return NULL;
  }
  if (!hook_lock(true))
    return NULL;
  icdlist_t *const head = &hook_view->heads[type];
  icdlist_t *const pos = idx == -1 ? head->prev : hook_pos(head, idx, 0);
  if (!pos || pos == head) {
    hook_unlock(ENOENT);
    return NULL;
  }

  struct hook_entry *const entry = icdlist_entry(pos, struct hook_entry, link);
  void *const handler = entry->handler;
  hook_release(entry);
  --hook_registry->lens[type];
  hook_shrink();
  hook_unlock(saved_errno);
  return handler;
}

int overlaysys_hook_clear(overlaysys_hook_type_t type) noexcept {
  const int saved_errno = errno;
  if ((unsigned)type >= HOOK_KINDS) {
    errno = EINVAL;
    return -1;
  }
  if (!hook_lock(true))
    return -1;
  icdlist_t *const head = &hook_view->heads[type];
  while (!icdlist_empty(head)) {
    icdlist_t *const node = head->next;
    struct hook_entry *const entry =
        icdlist_entry(node, struct hook_entry, link);
    hook_release(entry);
  }
  hook_registry->lens[type] = 0;
  hook_shrink();
  hook_unlock(saved_errno);
  return 0;
}

static int hook_copy_text(const char *text, char *ptr, size_t capacity) {
  const size_t len = strlen(text);
  if (capacity) {
    const size_t copied = len < capacity ? len : capacity - 1;
    memcpy(ptr, text, copied);
    ptr[copied] = '\0';
  }
  if (len >= capacity) {
    errno = ENOMEM;
    return -1;
  }
  return 0;
}

/* Resolve the mapped file, not a loader-relative name after a later chdir.
 * map_files also avoids the ambiguous newline escaping in maps pathnames. */
static char *hook_read_path(const void *handler, int *err) {
  FILE *const maps = fopen("/proc/self/maps", "re");
  if (!maps) {
    *err = errno;
    return NULL;
  }
  char *line = NULL, *path = NULL;
  size_t size = 0;
  for (;;) {
    errno = 0;
    if (getline(&line, &size, maps) < 0) {
      if (!feof(maps))
        *err = errno ? errno : EIO;
      break;
    }
    unsigned long start, end, inode;
    if (sscanf(line, "%lx-%lx %*s %*s %*s %lu", &start, &end, &inode) != 3 ||
        (uintptr_t)handler < start || (uintptr_t)handler >= end)
      continue;
    if (inode) {
      char link[sizeof("/proc/self/map_files/") + 4 * sizeof(uintptr_t) + 1];
      snprintf(link, sizeof(link), "/proc/self/map_files/%lx-%lx", start, end);
      path = realpath(link, NULL);
      if (!path)
        *err = errno;
    }
    break;
  }
  free(line);
  if (fclose(maps) && !*err)
    *err = errno;
  return path;
}

static int hook_resolve_name(const void *handler, char *ptr, size_t capacity) {
  const int saved_errno = errno;
  const Dwfl_Callbacks cbs = {
      .find_elf = dwfl_linux_proc_find_elf,
      .find_debuginfo = dwfl_standard_find_debuginfo,
  };
  errno = 0;
  Dwfl *dwfl = dwfl_begin(&cbs);
  if (!dwfl && errno == ENOMEM)
    return -1;

  int resolve_err = 0;
  if (dwfl) {
    const int report = dwfl_linux_proc_report(dwfl, getpid());
    if (report)
      resolve_err = report > 0 ? report : (errno ? errno : EIO);
    else if (dwfl_report_end(dwfl, NULL, NULL))
      resolve_err = errno ? errno : EIO;
  } else {
    resolve_err = errno ? errno : EIO;
  }
  const char *name = NULL;
  const Dwarf_Addr addr = (uintptr_t)handler;
  if (dwfl && !resolve_err) {
    Dwfl_Module *module = dwfl_addrmodule(dwfl, addr);
    if (module) {
      GElf_Off off = 0;
      GElf_Sym symbol = {};
      name =
          dwfl_module_addrinfo(module, addr, &off, &symbol, NULL, NULL, NULL);
      const unsigned int type = GELF_ST_TYPE(symbol.st_info);
      /* A preceding label is insufficient when its range excludes the hook. */
      if (!name || !*name ||
          (type != STT_FUNC && type != STT_GNU_IFUNC && type != STT_NOTYPE) ||
          (off && (type == STT_NOTYPE || off >= symbol.st_size)))
        name = NULL;

      if (!name) {
        Dwarf_Addr bias;
        Dwarf_Die *unit = dwfl_module_addrdie(module, addr, &bias);
        Dwarf_Die *scopes = NULL;
        const int cnt = unit ? dwarf_getscopes(unit, addr - bias, &scopes) : 0;
        /* An entry address can also belong to an inlined callee's first line.
         */
        for (int i = cnt - 1; i >= 0; --i) {
          if (dwarf_tag(&scopes[i]) != DW_TAG_subprogram)
            continue;
          const unsigned int attrs[] = {DW_AT_linkage_name,
                                        DW_AT_MIPS_linkage_name, DW_AT_name};
          for (size_t j = 0; j < sizeof(attrs) / sizeof(*attrs); ++j) {
            Dwarf_Attribute attr;
            Dwarf_Attribute *found =
                dwarf_attr_integrate(&scopes[i], attrs[j], &attr);
            if (found)
              name = dwarf_formstring(found);
            if (name && *name)
              break;
            name = NULL;
          }
          if (name)
            break;
        }
        free(scopes);
      }
    }
  }
  if (!name) {
    Dl_info info;
    if (dladdr(handler, &info) && info.dli_saddr == handler && info.dli_sname &&
        *info.dli_sname)
      name = info.dli_sname;
  }
  if (!name && resolve_err) {
    if (dwfl)
      dwfl_end(dwfl);
    errno = resolve_err;
    return -1;
  }
  if (!name)
    name = "?";
  const int res = hook_copy_text(name, ptr, capacity);
  const int err = errno;
  if (dwfl)
    dwfl_end(dwfl);
  errno = res ? err : saved_errno;
  return res;
}

enum hook_metadata { HOOK_PATH, HOOK_LIBNAME, HOOK_NAME };

static int hook_get_metadata(overlaysys_hook_type_t type, ptrdiff_t idx,
                             char *ptr, size_t capacity,
                             enum hook_metadata field, bool exclude_extension) {
  const int saved_errno = errno;
  if (ptr && capacity)
    ptr[0] = '\0';
  if ((unsigned)type >= HOOK_KINDS || idx < -1 || (!ptr && capacity)) {
    errno = EINVAL;
    return -1;
  }
  if (!hook_lock(false))
    return -1;
  const struct hook_entry *const entry = hook_at(type, idx);
  int res, err = 0;
  if (!entry) {
    res = hook_copy_text("", ptr, capacity);
  } else {
    const void *const handler = entry->handler;
    if (field == HOOK_NAME) {
      res = hook_resolve_name(handler, ptr, capacity);
    } else {
      char *const path = hook_read_path(handler, &err);
      const char *val = path ? path : "?";
      if (!err && path && field == HOOK_LIBNAME) {
        char *base = strrchr(path, '/');
        base = base ? base + 1 : path;
        if (exclude_extension) {
          char *const extension = strrchr(base, '.');
          if (extension && extension != base)
            *extension = '\0';
        }
        val = base;
      }
      res = err ? -1 : hook_copy_text(val, ptr, capacity);
      if (res && !err)
        err = errno;
      free(path);
    }
  }
  if (res && !err)
    err = errno;
  hook_unlock(res ? err : saved_errno);
  return res;
}

int overlaysys_hook_get_libpath(overlaysys_hook_type_t type, ptrdiff_t idx,
                                char *restrict ptr, size_t capacity) noexcept {
  return hook_get_metadata(type, idx, ptr, capacity, HOOK_PATH, false);
}

int overlaysys_hook_get_libname(overlaysys_hook_type_t type, ptrdiff_t idx,
                                char *restrict ptr, size_t capacity,
                                bool exclude_extension) noexcept {
  return hook_get_metadata(type, idx, ptr, capacity, HOOK_LIBNAME,
                           exclude_extension);
}

int overlaysys_hook_get_name(overlaysys_hook_type_t type, ptrdiff_t idx,
                             char *restrict ptr, size_t capacity) noexcept {
  return hook_get_metadata(type, idx, ptr, capacity, HOOK_NAME, false);
}

int hook_dispatch_syscall_hooks(long num, long a, long b, long c, long d,
                                long e, long f, long *res) {
  struct hook_data *const data = hook_read();
  if (!data)
    return 1;
  const uintptr_t delta =
      (uintptr_t)data -
      atomic_load_explicit(&hook_registry->canonical, memory_order_acquire);
  icdlist_t *const head = &data->heads[OVERLAYSYS_HOOK_TYPE_SYSCALL];
  for (icdlist_t *node = hook_link(head->next, delta); node != head;
       node = hook_link(node->next, delta)) {
    const struct hook_entry *const entry =
        icdlist_entry(node, struct hook_entry, link);
    int forward = 1;
    const struct cb_errno_scope scope = internal_hook_errno_enter();
    /* The syscall dispatch gate already excluded an active callback. */
    atomic_store_explicit(&syscall_user_cb_active, true, memory_order_relaxed);
    const long val = ((overlaysys_syscall_hook_t)entry->handler)(
        num, a, b, c, d, e, f, &forward);
    if (!forward && val == -1) {
      const int err = errno;
      *res = -err;
      internal_hook_errno_fail(scope, err);
    } else {
      if (!forward)
        *res = val;
      internal_hook_errno_leave(scope);
    }
    atomic_store_explicit(&syscall_user_cb_active, false, memory_order_relaxed);
    if (!forward)
      return 0;
  }
  return 1;
}

bool hook_has_syscall_epilogues(void) {
  return hook_registry &&
         hook_registry->lens[OVERLAYSYS_HOOK_TYPE_SYSCALL_EPILOGUE] != 0;
}

void hook_dispatch_syscall_epilogues(long num, long a, long b, long c, long d,
                                     long e, long f, long *ret) {
  struct hook_data *const data = hook_read();
  if (!data)
    return;
  const uintptr_t delta =
      (uintptr_t)data -
      atomic_load_explicit(&hook_registry->canonical, memory_order_acquire);
  icdlist_t *const head = &data->heads[OVERLAYSYS_HOOK_TYPE_SYSCALL_EPILOGUE];
  for (icdlist_t *node = hook_link(head->next, delta); node != head;
       node = hook_link(node->next, delta)) {
    const struct hook_entry *const entry =
        icdlist_entry(node, struct hook_entry, link);
    const struct cb_errno_scope scope = internal_hook_errno_enter();
    const int err = patcher_syscall_err_code(*ret);
    long orig_ret = err ? -1 : *ret;
    errno = err;
    /* Ordinary completion retains the syscall dispatch gate's eligibility. */
    atomic_store_explicit(&syscall_user_cb_active, true, memory_order_relaxed);
    ((overlaysys_syscall_epilogue_t)entry->handler)(num, a, b, c, d, e, f,
                                                    &orig_ret);
    if (orig_ret == -1) {
      int err = errno;
      if (err <= 0 || err > 4095)
        err = EINVAL;
      *ret = -(long)err;
      /* A later epilogue may recover; publish only the final error. */
      if (hook_link(node->next, delta) == head)
        internal_hook_errno_fail(scope, err);
      else
        internal_hook_errno_leave(scope);
    } else {
      *ret = orig_ret;
      internal_hook_errno_leave(scope);
    }
    atomic_store_explicit(&syscall_user_cb_active, false, memory_order_relaxed);
  }
}

bool hook_has_sig_hooks(void) {
  return hook_registry &&
         atomic_load_explicit(&hook_registry->lens[OVERLAYSYS_HOOK_TYPE_SIG],
                              memory_order_relaxed);
}

void hook_dispatch_sig_hooks(int sig, siginfo_t *info, void *ctx, int *forward,
                             const extsiginfo_t *extra) {
  struct hook_data *const data = hook_read();
  if (!data)
    return;
  const uintptr_t delta =
      (uintptr_t)data -
      atomic_load_explicit(&hook_registry->canonical, memory_order_acquire);
  icdlist_t *const head = &data->heads[OVERLAYSYS_HOOK_TYPE_SIG];
  for (icdlist_t *node = hook_link(head->next, delta); node != head;
       node = hook_link(node->next, delta)) {
    const struct hook_entry *const entry =
        icdlist_entry(node, struct hook_entry, link);
    internal_restore_app_errno();
    const bool cb = atomic_exchange_explicit(&syscall_user_cb_active, true,
                                             memory_order_relaxed);
    ((overlaysys_sig_hook_t)entry->handler)(sig, info, ctx, forward, extra);
    atomic_store_explicit(&syscall_user_cb_active, cb, memory_order_relaxed);
    /* The next hook or the enclosing signal wrapper restores errno. */
    if (!*forward)
      break;
  }
}

void hook_dispatch_clone_child_epilogues(void) {
  struct hook_data *const data = hook_read();
  if (!data)
    return;
  const uintptr_t delta =
      (uintptr_t)data -
      atomic_load_explicit(&hook_registry->canonical, memory_order_acquire);
  icdlist_t *const head =
      &data->heads[OVERLAYSYS_HOOK_TYPE_CLONE_CHILD_EPILOGUE];
  for (icdlist_t *node = hook_link(head->next, delta); node != head;
       node = hook_link(node->next, delta)) {
    const struct hook_entry *const entry =
        icdlist_entry(node, struct hook_entry, link);
    const struct cb_errno_scope scope = internal_hook_errno_enter();
    const bool cb = atomic_exchange_explicit(&syscall_user_cb_active, true,
                                             memory_order_relaxed);
    errno = 0;
    ((overlaysys_clone_child_epilogue_t)entry->handler)();
    internal_hook_errno_leave(scope);
    atomic_store_explicit(&syscall_user_cb_active, cb, memory_order_relaxed);
  }
}

void hook_dispatch_clone_parent_epilogues(pid_t child_tid) {
  struct hook_data *const data = hook_read();
  if (!data)
    return;
  const uintptr_t delta =
      (uintptr_t)data -
      atomic_load_explicit(&hook_registry->canonical, memory_order_acquire);
  icdlist_t *const head =
      &data->heads[OVERLAYSYS_HOOK_TYPE_CLONE_PARENT_EPILOGUE];
  for (icdlist_t *node = hook_link(head->next, delta); node != head;
       node = hook_link(node->next, delta)) {
    const struct hook_entry *const entry =
        icdlist_entry(node, struct hook_entry, link);
    const struct cb_errno_scope scope = internal_hook_errno_enter();
    const bool cb = atomic_exchange_explicit(&syscall_user_cb_active, true,
                                             memory_order_relaxed);
    errno = patcher_syscall_err_code(child_tid);
    ((overlaysys_clone_parent_epilogue_t)entry->handler)(child_tid);
    internal_hook_errno_leave(scope);
    atomic_store_explicit(&syscall_user_cb_active, cb, memory_order_relaxed);
  }
}
