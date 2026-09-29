#include <limits.h>
#include <string.h>

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/uio.h>

#include <linux/close_range.h>
#include <linux/sched.h>

#include "internal.h"

#define syscall_tracked_fds (syscall_fd_thread_owner->table->aliases)

struct syscall_saved_select_sets {
  struct syscall_saved_select_sets *next;
  size_t mapping_size, set_bytes;
  int nfds;
  void *user_output[3];
  /*
   * Original read/write/exception sets, followed by their working copies.
   */
  unsigned long sets[];
};

struct syscall_epoll_pending_event {
  struct epoll_event event;
  uint64_t token; // Zero preserves an unrecognized native event verbatim.
  bool verify_registration;
};

enum {
  SYSCALL_FD_IDX_BITS = 7,
  SYSCALL_FD_IDX_SLOTS = 1U << SYSCALL_FD_IDX_BITS,
  SYSCALL_FD_IDX_ROOTS = 8,
  SYSCALL_FD_IDX_KIND_MASK = 3,
  SYSCALL_EPOLL_TOKEN_MIN_BUCKETS = 64,
  SYSCALL_EPOLL_WATCH_MIN_BUCKETS = 16,
  SYSCALL_EPOLL_PENDING_BYTES = 4096,
  SYSCALL_EPOLL_FDINFO_BYTES = 256,
  SYSCALL_SELECT_STATUS_BYTES = 1024,
  SYSCALL_EPOLL_EVENT_BATCH =
      SYSCALL_EPOLL_PENDING_BYTES / sizeof(struct syscall_epoll_pending_event),
  SYSCALL_FD_STATE_PAGE_BYTES = 4096,
  SYSCALL_FD_STATE_HEADER_BYTES = 64,
  SYSCALL_FD_STATE_MIN_BYTES = 32,
  SYSCALL_FD_STATE_MAX_BYTES = 2048,
  SYSCALL_FD_STATE_CLASSES = 7,
};

/*
 * Cache identities in TLS before callbacks or deferred signal posting.
 * Each intercepted child refreshes both, including children with fresh TLS.
 */
__thread
    __attribute((tls_model("initial-exec"))) pid_t _overlaysys_syscall_self_tid,
    _overlaysys_syscall_self_pid;

static int (*syscall_vdso_clock_gettime)(clockid_t, struct timespec *);

static thread_local __attribute((
    tls_model("initial-exec"))) kernel_sigset_t syscall_clone_sigmask;

thread_local
    __attribute((tls_model("initial-exec"))) bool syscall_clone_sigmask_pending;

/*
 * Published under the action lock, which stays held across a private fork. TLS
 * identity also distinguishes the child when CLONE_SETTLS replaces TLS.
 */
static _Atomic uintptr_t syscall_fork_child_tls;
static struct {
  kernel_sigset_t mask;
  struct syscall_tracked_fd_owner *fd_owner;
  struct app_errno_state errno_state;
  bool cb, continuation;
  uint64_t hook_state;
  enum cb_errno_phase errno_phase;
} syscall_fork_state;

static_assert(ATOMIC_BOOL_LOCK_FREE == 2);

/*
 * Bit 0 is inherited dispatch eligibility; upper bits hold explicit disable
 * depth. A value of 1 permits user dispatch, subject to the callback guard.
 * Keep that temporary guard separate so callback entry does not update this
 * word, and signal-handler continuation preserves explicit suppression.
 */
static thread_local __attribute((
    tls_model("initial-exec"))) _Atomic uint64_t syscall_hook_state = 1;
static_assert(ATOMIC_LONG_LOCK_FREE == 2);

thread_local __attribute((
    tls_model("initial-exec"))) _Atomic bool syscall_user_cb_active,
    syscall_internal_emulation;

thread_local __attribute((tls_model(
    "initial-exec"))) _Atomic(struct app_errno_state) syscall_app_errno_state;
thread_local __attribute((tls_model(
    "initial-exec"))) _Atomic enum cb_errno_phase syscall_hook_errno_phase;

/*
 * Raw helpers bypass interception and return kernel results, including -errno.
 */

static __always_inline ssize_t syscall_raw_proc_vm_writev(
    pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
    const struct iovec *remote_iov, unsigned long riovcnt,
    unsigned long flags) {
  return util_syscall_no_intercept(SYS_process_vm_writev, pid, local_iov,
                                   liovcnt, remote_iov, riovcnt, flags);
}

static __always_inline int syscall_raw_pipe2(int pipefd[2], int flags) {
  return util_syscall_no_intercept(SYS_pipe2, pipefd, flags);
}

static __always_inline ssize_t syscall_raw_read(int fd, void *buf, size_t cnt) {
  return util_syscall_no_intercept(SYS_read, fd, buf, cnt);
}

static __always_inline ssize_t syscall_raw_write(int fd, const void *buf,
                                                 size_t cnt) {
  return util_syscall_no_intercept(SYS_write, fd, buf, cnt);
}

static __always_inline int syscall_raw_close(int fd) {
  return util_syscall_no_intercept(SYS_close, fd);
}

static __always_inline int syscall_raw_openat(int dirfd, const char *path,
                                              int flags, mode_t mode) {
  return util_syscall_no_intercept(SYS_openat, dirfd, path, flags, mode);
}

/*
 * Let the kernel validate both caller pointers without replacing fault
 * handlers. Return a copied byte count or a negative errno.
 *
 * Fallback requests must fit PIPE_BUF. Read the pipe in caller-selected units:
 * a fault may write part of one read yet report only -EFAULT, so separate reads
 * preserve the count of preceding complete records.
 */
static ssize_t syscall_copy_user_bytes(void *dest, const void *src, size_t size,
                                       size_t unit) {
  const struct iovec _local = {.iov_base = (void *)src, .iov_len = size};
  const struct iovec _remote = {.iov_base = dest, .iov_len = size};
  const pid_t _pid = _overlaysys_syscall_self_pid > 0
                         ? _overlaysys_syscall_self_pid
                         : internal_raw_getpid();
  long _copied = syscall_raw_proc_vm_writev(_pid, &_local, 1, &_remote, 1, 0);
  if (_copied >= 0 || _copied == -EFAULT)
    return _copied;

  /*
   * Some sandboxes deny process_vm_*. Small private pipe transfers use the
   * kernel's ordinary copy_from_user/copy_to_user permission checks instead.
   */
  static_assert(sizeof(struct kernel_sigaction) <= PIPE_BUF);
  log_verify(size <= PIPE_BUF);
  log_verify(!size || unit);
  int _pipe[2];
  const int _raw_ret = syscall_raw_pipe2(_pipe, O_CLOEXEC | O_NONBLOCK);
  if (patcher_syscall_err_code(_raw_ret))
    return _raw_ret;
  _copied = syscall_raw_write(_pipe[1], src, size);
  if (_copied == (ssize_t)size) {
    _copied = 0;
    while ((size_t)_copied < size) {
      const size_t _remaining = size - (size_t)_copied;
      const size_t _part = _remaining < unit ? _remaining : unit;
      const ssize_t _read =
          syscall_raw_read(_pipe[0], (char *)dest + _copied, _part);
      if (_read < 0) {
        if (!_copied)
          _copied = _read;
        break;
      }
      _copied += _read;
      if ((size_t)_read != _part)
        break;
    }
  } else if (_copied >= 0)
    _copied = -EFAULT; // No destination bytes were written yet.
  syscall_raw_close(_pipe[0]);
  syscall_raw_close(_pipe[1]);
  return _copied;
}

/*
 * Require a complete transfer; report a partial copy as EFAULT.
 */
int syscall_copy_user_mem(void *dest, const void *src, size_t size) {
  const ssize_t _copied = syscall_copy_user_bytes(dest, src, size, size);
  if (_copied < 0)
    return _copied;
  return (size_t)_copied == size ? 0 : -EFAULT;
}

static __always_inline int syscall_raw_signalfd4(int fd,
                                                 const kernel_sigset_t *mask,
                                                 size_t size, int flags) {
  return util_syscall_no_intercept(SYS_signalfd4, fd, mask, size, flags);
}

static __always_inline int syscall_raw_epoll_ctl(int epfd, int op, int fd,
                                                 struct epoll_event *event) {
  return util_syscall_no_intercept(SYS_epoll_ctl, epfd, op, fd, event);
}

enum syscall_tracked_fd_kind {
  SYSCALL_TRACKED_NONE,
  SYSCALL_TRACKED_SIGNALFD,
  SYSCALL_TRACKED_EPOLL
};
static_assert(SYSCALL_TRACKED_SIGNALFD == 1 && SYSCALL_TRACKED_EPOLL == 2);

struct syscall_tracked_fd_object;

struct syscall_tracked_epoll_watch;

struct syscall_epoll_event_version {
  struct syscall_epoll_event_version *next;
  struct syscall_epoll_event_version *idx_next;
  struct syscall_tracked_fd_object *owner;
  struct syscall_tracked_epoll_watch *watch;
  struct syscall_epoll_event_version **owner_link;
  struct syscall_epoll_event_version *retired_next;
  struct syscall_epoll_event_version **retired_link;
  uint64_t token;
  epoll_data_t data;
  bool oneshot, armed, native_armed, retired;
  bool fdinfo_registered, fdinfo_requested;
};

struct syscall_tracked_epoll_watch {
  struct syscall_tracked_epoll_watch *next;
  struct syscall_tracked_epoll_watch **prev;
  struct syscall_tracked_epoll_watch *target_next, *idx_next;
  struct syscall_tracked_fd_object *target;
  struct syscall_epoll_event_version *version;
  uint32_t events;
  int fd;
  unsigned long edge_seq;
};

struct syscall_tracked_fd_object {
  struct syscall_tracked_fd_object *next;
  enum syscall_tracked_fd_kind kind;
  size_t aliases, wait_refs;
  unsigned long mask;
  struct syscall_tracked_epoll_watch *watches;
  struct syscall_tracked_epoll_watch **watch_buckets;
  size_t watch_capacity, watch_cnt;
  struct syscall_tracked_epoll_watch *incoming_watches;
  struct syscall_epoll_event_version *versions;
  struct syscall_epoll_pending_event *pending_epoll_events;
  size_t pending_epoll_cnt;
  size_t pending_epoll_capacity;
  unsigned long pending_epoll_seq;
  bool retired, watch_shrink_failed;
  uint32_t watch_shrink_retry;
};

struct syscall_tracked_fd_alias {
  struct syscall_tracked_fd_alias *next, **prev;
  struct syscall_tracked_fd_object *object;
  int fd;
};

static_assert(sizeof(struct syscall_tracked_epoll_watch) == 64);

static_assert(sizeof(struct syscall_epoll_event_version) == 80);

static_assert(sizeof(struct syscall_tracked_fd_object) == 128);

struct syscall_fd_idx_branch {
  _Atomic(void *) children[SYSCALL_FD_IDX_SLOTS];
};

struct syscall_fd_idx_leaf {
  /*
   * Trusted alias pointers carry their kind in two alignment bits. Lock-free
   * readers inspect only kind/presence, never the alias.
   */
  _Atomic uintptr_t entries[SYSCALL_FD_IDX_SLOTS];
};

struct syscall_fd_idx {
  _Atomic(void *) roots[SYSCALL_FD_IDX_ROOTS];
  /*
   * The usual low FD range retains the existing two-load fast path.
   */
  _Atomic(struct syscall_fd_idx_leaf *) low;
};

struct syscall_tracked_fd_table {
  struct syscall_tracked_fd_table *next;
  struct syscall_tracked_fd_alias *aliases;
  size_t owners;
  _Atomic int hook_fd;
  struct syscall_fd_idx idx;
};

struct syscall_tracked_fd_owner {
  struct syscall_tracked_fd_owner *next;
  struct syscall_tracked_fd_table *table;
  pid_t thread;
  bool clone_wrapper_requested;
  struct syscall_epoll_wait_scope *epoll_scopes;
  struct syscall_saved_select_sets *saved_select_sets;
  kernel_sigset_t clone_mask;
};

static_assert(sizeof(struct syscall_tracked_fd_owner) == 48);

static struct syscall_tracked_fd_table *syscall_fd_tables;

static struct syscall_tracked_fd_owner *syscall_fd_owners;

static thread_local __attribute((tls_model(
    "initial-exec"))) struct syscall_tracked_fd_owner *syscall_fd_thread_owner,
    *syscall_fd_clone_owner;

int syscall_resize_hook_backing(size_t bytes) {
  if (!syscall_fd_thread_owner)
    return hook_resize_backing(hook_backing_fd, bytes);
  const bool internal =
      atomic_load_explicit(&syscall_internal_emulation, memory_order_relaxed);
  kernel_sigset_t mask;
  sig_lock_rt_sigaction(&mask);
  const int err =
      hook_resize_backing(syscall_fd_thread_owner->table->hook_fd, bytes);
  sig_unlock_rt_sigaction(&mask);
  atomic_store_explicit(&syscall_internal_emulation, internal,
                        memory_order_relaxed);
  return err;
}

static struct syscall_tracked_fd_object *syscall_retired_fd_objects;

static _Atomic size_t syscall_nr_signalfds;

static _Atomic size_t syscall_nr_pending_epoll_events;

/*
 * Scalar cookies are never treated as application or internal pointers.
 */
static uint64_t syscall_next_epoll_token = UINT64_C(0x4f53000000000000);

struct syscall_fd_state_page {
  struct syscall_fd_state_page *next, *prev;
  void *free;
  unsigned int size_class, avail;
};

static_assert(sizeof(struct syscall_fd_state_page) <=
              SYSCALL_FD_STATE_HEADER_BYTES);

static_assert(SYSCALL_FD_STATE_MIN_BYTES << (SYSCALL_FD_STATE_CLASSES - 1) ==
              SYSCALL_FD_STATE_MAX_BYTES);

static struct syscall_fd_state_page
    *syscall_fd_state_avail[SYSCALL_FD_STATE_CLASSES];

static struct syscall_fd_state_page
    *syscall_fd_state_empty[SYSCALL_FD_STATE_CLASSES];

static void *syscall_fd_state_page_spare;

/*
 * All accesses hold the signal/FD lock. Slots stay at stable addresses and use
 * only private raw mappings, so interrupted application allocators are never
 * reentered.
 *
 * Keep one empty page per size class and one page-sized block for event batches
 * to avoid mmap/munmap churn when epoll objects are replaced.
 */
static void *syscall_alloc_fd_state(size_t size) {
  if (size > SYSCALL_FD_STATE_MAX_BYTES) {
    if (size <= SYSCALL_FD_STATE_PAGE_BYTES && syscall_fd_state_page_spare) {
      void *const _state = syscall_fd_state_page_spare;
      syscall_fd_state_page_spare = NULL;
      __builtin_memset(_state, 0, SYSCALL_FD_STATE_PAGE_BYTES);
      return _state;
    }
    void *const _state = internal_raw_mmap(NULL, size, PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    const int _err = patcher_syscall_err_code((long)_state);
    if (_err) {
      errno = _err;
      return NULL;
    }
    return _state;
  }
  unsigned int _class = 0, _slot_size = SYSCALL_FD_STATE_MIN_BYTES;
  while (_slot_size < size) {
    _slot_size <<= 1;
    ++_class;
  }
  struct syscall_fd_state_page *_page = syscall_fd_state_avail[_class];
  if (!_page) {
    _page = internal_raw_mmap(NULL, SYSCALL_FD_STATE_PAGE_BYTES,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    const int _err = patcher_syscall_err_code((long)_page);
    if (_err) {
      errno = _err;
      return NULL;
    }
    _page->size_class = _class;
    _page->avail =
        (SYSCALL_FD_STATE_PAGE_BYTES - SYSCALL_FD_STATE_HEADER_BYTES) /
        _slot_size;
    for (unsigned int i = 0; i < _page->avail; ++i) {
      void *const _slot =
          (char *)_page + SYSCALL_FD_STATE_HEADER_BYTES + i * _slot_size;
      __builtin_memcpy(_slot, &_page->free, sizeof(_page->free));
      _page->free = _slot;
    }
    syscall_fd_state_avail[_class] = _page;
  }
  if (syscall_fd_state_empty[_class] == _page)
    syscall_fd_state_empty[_class] = NULL;
  void *const _state = _page->free;
  __builtin_memcpy(&_page->free, _state, sizeof(_page->free));
  if (!--_page->avail) {
    syscall_fd_state_avail[_class] = _page->next;
    if (_page->next)
      _page->next->prev = NULL;
    _page->next = _page->prev = NULL;
  }
  __builtin_memset(_state, 0, _slot_size);
  return _state;
}

static void syscall_free_fd_state(void *state, size_t size) {
  if (!state)
    return;
  if (size > SYSCALL_FD_STATE_MAX_BYTES) {
    if (size <= SYSCALL_FD_STATE_PAGE_BYTES && !syscall_fd_state_page_spare) {
      syscall_fd_state_page_spare = state;
      return;
    }
    internal_raw_munmap(state, size);
    return;
  }
  struct syscall_fd_state_page *const _page =
      (void *)((uintptr_t)state &
               ~(uintptr_t)(SYSCALL_FD_STATE_PAGE_BYTES - 1));
  const unsigned int _class = _page->size_class;
  const unsigned int _slot_size = SYSCALL_FD_STATE_MIN_BYTES << _class;
  if (!_page->avail) {
    _page->next = syscall_fd_state_avail[_class];
    if (_page->next)
      _page->next->prev = _page;
    syscall_fd_state_avail[_class] = _page;
  }
  __builtin_memcpy(state, &_page->free, sizeof(_page->free));
  _page->free = state;
  if (++_page->avail !=
      (SYSCALL_FD_STATE_PAGE_BYTES - SYSCALL_FD_STATE_HEADER_BYTES) /
          _slot_size)
    return;
  if (!syscall_fd_state_empty[_class]) {
    syscall_fd_state_empty[_class] = _page;
    return;
  }
  if (_page->prev)
    _page->prev->next = _page->next;
  else
    syscall_fd_state_avail[_class] = _page->next;
  if (_page->next)
    _page->next->prev = _page->prev;
  internal_raw_munmap(_page, SYSCALL_FD_STATE_PAGE_BYTES);
}

static_assert(alignof(struct syscall_tracked_fd_alias) >
              SYSCALL_FD_IDX_KIND_MASK);

static_assert(sizeof(struct syscall_tracked_fd_alias) == 32);

static_assert(sizeof(struct syscall_fd_idx_branch) == 1024);

static_assert(sizeof(struct syscall_fd_idx_leaf) == 1024);

/*
 * A single mutation runs at a time. Global spares avoid reserving a complete
 * spare path in every private FD table. Fork copies their private mappings;
 * failed copies leave unused, initialized spares available for the next call.
 */
static struct syscall_fd_idx_branch *syscall_fd_idx_spare_branches[3];

static struct syscall_fd_idx_leaf *syscall_fd_idx_spare_leaf;

static int syscall_reserve_fd_idx_locked(void) {
  for (size_t i = 0; i < 3; ++i) {
    if (syscall_fd_idx_spare_branches[i])
      continue;
    struct syscall_fd_idx_branch *const _branch =
        syscall_alloc_fd_state(sizeof(*_branch));
    if (!_branch)
      return -ENOMEM;
    for (size_t j = 0; j < SYSCALL_FD_IDX_SLOTS; ++j)
      atomic_init(&_branch->children[j], NULL);
    syscall_fd_idx_spare_branches[i] = _branch;
  }
  if (!syscall_fd_idx_spare_leaf) {
    struct syscall_fd_idx_leaf *const _leaf =
        syscall_alloc_fd_state(sizeof(*_leaf));
    if (!_leaf)
      return -ENOMEM;
    for (size_t i = 0; i < SYSCALL_FD_IDX_SLOTS; ++i)
      atomic_init(&_leaf->entries[i], 0);
    syscall_fd_idx_spare_leaf = _leaf;
  }
  return 0;
}

static struct syscall_fd_idx_leaf *
syscall_lookup_fd_idx_leaf(const struct syscall_fd_idx *idx, int fd) {
  if (fd < 0)
    return NULL;
  const unsigned int _fd = fd;
  if (_fd < SYSCALL_FD_IDX_SLOTS)
    return atomic_load_explicit(&idx->low, memory_order_acquire);
  void *_node =
      atomic_load_explicit(&idx->roots[_fd >> 28], memory_order_acquire);
  for (int _shift = 21; _node && _shift >= 7; _shift -= SYSCALL_FD_IDX_BITS) {
    const struct syscall_fd_idx_branch *const _branch = _node;
    _node = atomic_load_explicit(
        &_branch->children[(_fd >> _shift) & (SYSCALL_FD_IDX_SLOTS - 1)],
        memory_order_acquire);
  }
  return _node;
}

/*
 * The table owner's reference pins every index node. The API contract forbids
 * signal handlers from splitting this owner's table during lookup; this is a
 * caller requirement, not a runtime guard. Entries may race a removal; callers
 * classify here and recheck the pointer under the lock.
 */
static bool syscall_is_tracked_fd(int fd, bool sig_only) {
  if (!syscall_fd_thread_owner || !syscall_fd_thread_owner->table)
    return false;
  if (!sig_only && fd >= 0 &&
      fd == atomic_load_explicit(&syscall_fd_thread_owner->table->hook_fd,
                                 memory_order_relaxed))
    return true;
  const struct syscall_fd_idx_leaf *const _leaf =
      syscall_lookup_fd_idx_leaf(&syscall_fd_thread_owner->table->idx, fd);
  if (!_leaf)
    return false;
  const uintptr_t _entry = atomic_load_explicit(
      &_leaf->entries[(unsigned int)fd & (SYSCALL_FD_IDX_SLOTS - 1)],
      memory_order_acquire);
  return sig_only
             ? (_entry & SYSCALL_FD_IDX_KIND_MASK) == SYSCALL_TRACKED_SIGNALFD
             : _entry != 0;
}

static struct syscall_tracked_fd_alias *syscall_find_fd_alias_locked(int fd) {
  if (!syscall_fd_thread_owner || !syscall_fd_thread_owner->table)
    return NULL;
  const struct syscall_fd_idx_leaf *const _leaf =
      syscall_lookup_fd_idx_leaf(&syscall_fd_thread_owner->table->idx, fd);
  if (!_leaf)
    return NULL;
  const uintptr_t _entry = atomic_load_explicit(
      &_leaf->entries[(unsigned int)fd & (SYSCALL_FD_IDX_SLOTS - 1)],
      memory_order_relaxed);
  return (
      struct syscall_tracked_fd_alias *)(_entry &
                                         ~(uintptr_t)SYSCALL_FD_IDX_KIND_MASK);
}

static struct syscall_tracked_fd_object *syscall_find_fd_locked(int fd) {
  const struct syscall_tracked_fd_alias *const _alias =
      syscall_find_fd_alias_locked(fd);
  return _alias ? _alias->object : NULL;
}

/*
 * Known destinations with an existing leaf cannot allocate an index path.
 * Unknown results from dup/fcntl/create still reserve the complete spare path.
 */
static int
syscall_reserve_fd_idx_for_fd_locked(struct syscall_tracked_fd_table *table,
                                     int fd) {
  return fd < 0 || syscall_lookup_fd_idx_leaf(&table->idx, fd)
             ? 0
             : syscall_reserve_fd_idx_locked();
}

/*
 * Call after linking initialized alias/object metadata on insertion and before
 * freeing the object on removal. The pre-syscall reservation makes publication
 * infallible even for an unexpected high FD returned by the kernel.
 */
static void
syscall_publish_fd_idx_locked(struct syscall_tracked_fd_table *table, int fd,
                              struct syscall_tracked_fd_alias *alias) {
  log_verify(fd >= 0);
  const unsigned int _fd = fd;
  struct syscall_fd_idx_leaf *_leaf;
  if (!alias) {
    _leaf = syscall_lookup_fd_idx_leaf(&table->idx, fd);
    if (!_leaf)
      return;
  } else {
    _Atomic(void *) *_slot = &table->idx.roots[_fd >> 28];
    for (size_t i = 0; i < 3; ++i) {
      struct syscall_fd_idx_branch *_branch =
          atomic_load_explicit(_slot, memory_order_relaxed);
      if (!_branch) {
        _branch = syscall_fd_idx_spare_branches[i];
        log_verify(_branch);
        syscall_fd_idx_spare_branches[i] = NULL;
        atomic_store_explicit(_slot, _branch, memory_order_release);
      }
      _slot = &_branch->children[(_fd >> (21 - i * SYSCALL_FD_IDX_BITS)) &
                                 (SYSCALL_FD_IDX_SLOTS - 1)];
    }
    _leaf = atomic_load_explicit(_slot, memory_order_relaxed);
    if (!_leaf) {
      _leaf = syscall_fd_idx_spare_leaf;
      log_verify(_leaf);
      syscall_fd_idx_spare_leaf = NULL;
      atomic_store_explicit(_slot, _leaf, memory_order_release);
      if (_fd < SYSCALL_FD_IDX_SLOTS)
        atomic_store_explicit(&table->idx.low, _leaf, memory_order_release);
    }
  }
  const uintptr_t _entry = alias ? (uintptr_t)alias | alias->object->kind : 0;
  atomic_store_explicit(&_leaf->entries[_fd & (SYSCALL_FD_IDX_SLOTS - 1)],
                        _entry, memory_order_release);
}

static void
syscall_destroy_fd_idx_branch_locked(struct syscall_fd_idx_branch *branch,
                                     unsigned int depth) {
  for (size_t i = 0; i < SYSCALL_FD_IDX_SLOTS; ++i) {
    void *const _child =
        atomic_load_explicit(&branch->children[i], memory_order_relaxed);
    if (!_child)
      continue;
    if (depth == 2)
      syscall_free_fd_state(_child, sizeof(struct syscall_fd_idx_leaf));
    else
      syscall_destroy_fd_idx_branch_locked(_child, depth + 1);
  }
  syscall_free_fd_state(branch, sizeof(*branch));
}

/*
 * Only unpublished tables or tables with no remaining owners reach here. Empty
 * live leaves deliberately remain linked: reclaiming them concurrently would
 * require a separate reader lifetime scheme on every ordinary read.
 */
static void syscall_destroy_fd_idx_locked(struct syscall_fd_idx *idx) {
  atomic_store_explicit(&idx->low, NULL, memory_order_relaxed);
  for (size_t i = 0; i < SYSCALL_FD_IDX_ROOTS; ++i) {
    struct syscall_fd_idx_branch *const _branch =
        atomic_load_explicit(&idx->roots[i], memory_order_relaxed);
    if (_branch)
      syscall_destroy_fd_idx_branch_locked(_branch, 0);
    atomic_store_explicit(&idx->roots[i], NULL, memory_order_relaxed);
  }
}

/*
 * Fresh-table initialization only. The alias-copy loop publishes its new nodes;
 * copying the source index would incorrectly share alias identities.
 */
static void syscall_init_fd_idx_locked(struct syscall_tracked_fd_table *dest) {
  for (size_t i = 0; i < SYSCALL_FD_IDX_ROOTS; ++i)
    atomic_init(&dest->idx.roots[i], NULL);
  atomic_init(&dest->idx.low, NULL);
}

struct syscall_epoll_scope_ref {
  struct syscall_epoll_scope_ref *next;
  struct syscall_tracked_fd_object *object;
};

struct syscall_epoll_wait_scope {
  struct syscall_epoll_wait_scope *owner_next;
  struct syscall_epoll_wait_scope *active_next;
  struct syscall_epoll_wait_scope **active_link;
  struct syscall_tracked_fd_owner *owner;
  struct syscall_epoll_scope_ref *refs;
  int fd;
};

static struct syscall_epoll_wait_scope *syscall_active_epoll_scopes;

static size_t syscall_nr_active_epoll_scopes;

static struct syscall_epoll_scope_ref *syscall_free_epoll_scope_refs;

static size_t syscall_nr_free_epoll_scope_refs;

static bool
syscall_epoll_scope_has_object(const struct syscall_epoll_wait_scope *scope,
                               const struct syscall_tracked_fd_object *object) {
  for (const struct syscall_epoll_scope_ref *_ref = scope->refs; _ref;
       _ref = _ref->next)
    if (_ref->object == object)
      return true;
  return false;
}

static int syscall_reserve_epoll_scope_refs_locked(size_t cnt) {
  while (syscall_nr_free_epoll_scope_refs < cnt) {
    struct syscall_epoll_scope_ref *const _ref =
        syscall_alloc_fd_state(sizeof(*_ref));
    if (!_ref)
      return -ENOMEM;
    _ref->next = syscall_free_epoll_scope_refs;
    syscall_free_epoll_scope_refs = _ref;
    ++syscall_nr_free_epoll_scope_refs;
  }
  return 0;
}

/*
 * One spare per active scope covers one fd mutation with an unknown result
 * number. When no scopes remain active, retain one spare for the next wait.
 */
static void syscall_trim_epoll_scope_refs_locked(void) {
  const size_t _limit =
      syscall_nr_active_epoll_scopes ? syscall_nr_active_epoll_scopes : 1;
  while (syscall_nr_free_epoll_scope_refs > _limit) {
    struct syscall_epoll_scope_ref *const _ref = syscall_free_epoll_scope_refs;
    syscall_free_epoll_scope_refs = _ref->next;
    --syscall_nr_free_epoll_scope_refs;
    syscall_free_fd_state(_ref, sizeof(*_ref));
  }
}

static void
syscall_bind_epoll_scope_locked(struct syscall_epoll_wait_scope *scope,
                                struct syscall_tracked_fd_object *object) {
  if (!object || object->kind != SYSCALL_TRACKED_EPOLL ||
      syscall_epoll_scope_has_object(scope, object))
    return;
  log_verify(syscall_free_epoll_scope_refs && syscall_nr_free_epoll_scope_refs);
  struct syscall_epoll_scope_ref *const _ref = syscall_free_epoll_scope_refs;
  syscall_free_epoll_scope_refs = _ref->next;
  --syscall_nr_free_epoll_scope_refs;
  _ref->object = object;
  _ref->next = scope->refs;
  scope->refs = _ref;
  ++object->wait_refs;
}

/*
 * Reserve before entering native epoll_wait. Scopes belong to the thread owner,
 * so siglongjmp cannot leave dangling stack pointers; abandoned scopes remain
 * until thread exit or a private child discards its copied stack.
 */
static int
syscall_begin_epoll_scope_locked(int fd,
                                 struct syscall_epoll_wait_scope **res) {
  *res = NULL;
  if (fd < 0)
    return 0;
  struct syscall_epoll_wait_scope *_scope =
      syscall_fd_thread_owner->epoll_scopes;
  while (_scope && _scope->active_link)
    _scope = _scope->owner_next;
  const bool _new = !_scope;
  if (_new) {
    _scope = syscall_alloc_fd_state(sizeof(*_scope));
    if (!_scope)
      return -ENOMEM;
  }
  struct syscall_tracked_fd_object *const _object = syscall_find_fd_locked(fd);
  if (_object && _object->kind == SYSCALL_TRACKED_EPOLL) {
    const int _err = syscall_reserve_epoll_scope_refs_locked(1);
    if (_err) {
      if (_new)
        syscall_free_fd_state(_scope, sizeof(*_scope));
      return _err;
    }
  }
  if (_new) {
    _scope->owner_next = syscall_fd_thread_owner->epoll_scopes;
    syscall_fd_thread_owner->epoll_scopes = _scope;
  }
  _scope->owner = syscall_fd_thread_owner;
  _scope->fd = fd;
  _scope->active_next = syscall_active_epoll_scopes;
  _scope->active_link = &syscall_active_epoll_scopes;
  if (_scope->active_next)
    _scope->active_next->active_link = &_scope->active_next;
  syscall_active_epoll_scopes = _scope;
  ++syscall_nr_active_epoll_scopes;
  syscall_bind_epoll_scope_locked(_scope, _object);
  *res = _scope;
  return 0;
}

/*
 * fd < 0 denotes an unknown result number from create/dup/F_DUPFD. object ==
 * NULL denotes a not-yet-created epoll OFD; known non-epoll sources need no
 * protection. This intentionally reserves a conservative upper bound across
 * active scopes in the current table before native mutation begins.
 */
static int syscall_reserve_epoll_scope_bindings_locked(
    int fd, const struct syscall_tracked_fd_object *object) {
  if (object && object->kind != SYSCALL_TRACKED_EPOLL)
    return 0;
  size_t _needed = 0;
  for (const struct syscall_epoll_wait_scope *_scope =
           syscall_active_epoll_scopes;
       _scope; _scope = _scope->active_next)
    if (_scope->owner->table == syscall_fd_thread_owner->table &&
        (fd < 0 || _scope->fd == fd) &&
        (!object || !syscall_epoll_scope_has_object(_scope, object)))
      ++_needed;
  const int _err = syscall_reserve_epoll_scope_refs_locked(_needed);
  if (_err)
    syscall_trim_epoll_scope_refs_locked();
  return _err;
}

/*
 * Publish after native success, under the lock, before releasing the previous
 * alias or its watches and versions.
 *
 * In dup2/dup3, the source epoll may watch the replaced target. Releasing that
 * target can retire a source cookie, so pin the source first. A newly created
 * object must be initialized before binding; it has no previous alias or native
 * tokens until later intercepted epoll_ctl calls.
 */
static void syscall_publish_epoll_scope_binding_locked(
    int fd, struct syscall_tracked_fd_object *object) {
  if (!object || object->kind != SYSCALL_TRACKED_EPOLL)
    return;
  for (struct syscall_epoll_wait_scope *_scope = syscall_active_epoll_scopes;
       _scope; _scope = _scope->active_next)
    if (_scope->owner->table == syscall_fd_thread_owner->table &&
        _scope->fd == fd)
      syscall_bind_epoll_scope_locked(_scope, object);
}

/*
 * Before unshare/close_range_UNSHARE, reserve one possible binding per active
 * scope of the caller. After success and owner->table replacement, refresh
 * those scopes BEFORE discarding the old table or removing closed-range
 * aliases. Old candidate OFDs remain pinned, but old table aliases are not
 * falsely kept alive by a metadata-only reference.
 */
static int syscall_reserve_epoll_scope_table_move_locked(void) {
  size_t _needed = 0;
  for (const struct syscall_epoll_wait_scope *_scope =
           syscall_fd_thread_owner->epoll_scopes;
       _scope; _scope = _scope->owner_next)
    _needed += _scope->active_link != NULL;
  return syscall_reserve_epoll_scope_refs_locked(_needed);
}

static void syscall_refresh_epoll_scope_table_locked(void) {
  for (struct syscall_epoll_wait_scope *_scope =
           syscall_fd_thread_owner->epoll_scopes;
       _scope; _scope = _scope->owner_next)
    if (_scope->active_link)
      syscall_bind_epoll_scope_locked(_scope,
                                      syscall_find_fd_locked(_scope->fd));
}

/*
 * End only after decoding/copying native events or transferring them to an
 * independently retained buffer. The caller runs object/version collectors
 * afterwards, once none of its local variables still needs those objects.
 */
static void
syscall_end_epoll_scope_locked(struct syscall_epoll_wait_scope *scope) {
  if (!scope)
    return;
  log_verify(scope->active_link && syscall_nr_active_epoll_scopes);
  *scope->active_link = scope->active_next;
  if (scope->active_next)
    scope->active_next->active_link = scope->active_link;
  scope->active_next = NULL;
  scope->active_link = NULL;
  --syscall_nr_active_epoll_scopes;
  while (scope->refs) {
    struct syscall_epoll_scope_ref *const _ref = scope->refs;
    scope->refs = _ref->next;
    log_verify(_ref->object->wait_refs);
    --_ref->object->wait_refs;
    _ref->object = NULL;
    _ref->next = syscall_free_epoll_scope_refs;
    syscall_free_epoll_scope_refs = _ref;
    ++syscall_nr_free_epoll_scope_refs;
  }
  syscall_trim_epoll_scope_refs_locked();
}

/*
 * Release scopes before freeing their owner or collecting OFDs. A private child
 * preserves the calling owner's scopes only when continuing its copied stack;
 * sibling scopes and new-stack continuations have no surviving wait.
 */
static void syscall_clear_epoll_scopes_owner_locked(
    struct syscall_tracked_fd_owner *owner) {
  while (owner->epoll_scopes) {
    struct syscall_epoll_wait_scope *const _scope = owner->epoll_scopes;
    owner->epoll_scopes = _scope->owner_next;
    if (_scope->active_link)
      syscall_end_epoll_scope_locked(_scope);
    syscall_free_fd_state(_scope, sizeof(*_scope));
  }
}

static struct syscall_epoll_event_version **syscall_epoll_token_buckets;

static size_t syscall_epoll_token_capacity, syscall_epoll_token_cnt;

static size_t syscall_epoll_token_shrink_retry = SIZE_MAX;

static size_t syscall_epoll_token_bucket(uint64_t token, size_t capacity) {
  /*
   * Mix all bits: long-lived versions may survive many cycles of sequential
   * token allocation, so low token bits alone can concentrate old records.
   */
  token ^= token >> 33;
  token *= UINT64_C(0xff51afd7ed558ccd);
  token ^= token >> 33;
  token *= UINT64_C(0xc4ceb9fe1a85ec53);
  token ^= token >> 33;
  return (size_t)token & (capacity - 1);
}

static int syscall_resize_epoll_token_idx_locked(size_t capacity) {
  if (capacity > SIZE_MAX / sizeof(*syscall_epoll_token_buckets))
    return -ENOMEM;
  struct syscall_epoll_event_version **const _buckets =
      syscall_alloc_fd_state(capacity * sizeof(*_buckets));
  if (!_buckets)
    return -ENOMEM;
  for (size_t i = 0; i < syscall_epoll_token_capacity; ++i) {
    struct syscall_epoll_event_version *_version =
        syscall_epoll_token_buckets[i];
    while (_version) {
      struct syscall_epoll_event_version *const _next = _version->idx_next;
      const size_t _bucket =
          syscall_epoll_token_bucket(_version->token, capacity);
      _version->idx_next = _buckets[_bucket];
      _buckets[_bucket] = _version;
      _version = _next;
    }
  }
  if (syscall_epoll_token_buckets)
    syscall_free_fd_state(syscall_epoll_token_buckets,
                          syscall_epoll_token_capacity *
                              sizeof(*syscall_epoll_token_buckets));
  syscall_epoll_token_buckets = _buckets;
  syscall_epoll_token_capacity = capacity;
  return 0;
}

/*
 * Call before a native epoll_ctl that may publish one new version. Growing
 * after a successful syscall would leave a kernel cookie that cannot decode.
 * Failed reservations leave the complete old index usable.
 */
static int syscall_reserve_epoll_version_idx_locked(void) {
  if (syscall_epoll_token_cnt < syscall_epoll_token_capacity / 2)
    return 0;
  if (syscall_epoll_token_capacity > SIZE_MAX / 2)
    return -ENOMEM;
  const size_t _capacity = syscall_epoll_token_capacity
                               ? syscall_epoll_token_capacity * 2
                               : SYSCALL_EPOLL_TOKEN_MIN_BUCKETS;
  const int _res = syscall_resize_epoll_token_idx_locked(_capacity);
  if (!_res)
    syscall_epoll_token_shrink_retry = SIZE_MAX;
  return _res;
}

/*
 * Commit only after native success and after linking the owner's version list.
 * reserve_epoll_version_idx_locked made this step allocation-free.
 */
static void
syscall_idx_epoll_version_locked(struct syscall_tracked_fd_object *owner,
                                 struct syscall_epoll_event_version *version) {
  log_verify(syscall_epoll_token_cnt < syscall_epoll_token_capacity / 2);
  const size_t _bucket =
      syscall_epoll_token_bucket(version->token, syscall_epoll_token_capacity);
  version->owner = owner;
  version->idx_next = syscall_epoll_token_buckets[_bucket];
  syscall_epoll_token_buckets[_bucket] = version;
  ++syscall_epoll_token_cnt;
}

static struct syscall_epoll_event_version *
syscall_find_epoll_version_locked(uint64_t token,
                                  struct syscall_tracked_fd_object **owner) {
  if (owner)
    *owner = NULL;
  if (!syscall_epoll_token_capacity)
    return NULL;
  const size_t _bucket =
      syscall_epoll_token_bucket(token, syscall_epoll_token_capacity);
  for (struct syscall_epoll_event_version *_version =
           syscall_epoll_token_buckets[_bucket];
       _version; _version = _version->idx_next)
    if (_version->token == token) {
      if (owner)
        *owner = _version->owner;
      return _version;
    }
  return NULL;
}

/*
 * One locked fdinfo scan resolves all requested tokens through the index. Count
 * duplicate tokens once; prune_pending_epoll_events_locked resets the scratch
 * flags and clears requests even when scanning fails.
 */
static bool syscall_match_epoll_registration_locked(
    uint64_t val, uint64_t token, struct syscall_tracked_fd_object *object,
    size_t *remaining) {
  if (!object)
    return val == token;
  struct syscall_epoll_event_version *const _version =
      syscall_find_epoll_version_locked(val, NULL);
  if (_version && _version->owner == object && _version->fdinfo_requested &&
      !_version->fdinfo_registered) {
    _version->fdinfo_registered = true;
    --*remaining;
  }
  return !*remaining;
}

/*
 * A NULL object checks one token and returns 1 when it is found. Otherwise a
 * stream marks requested tokens through their existing hash index, stopping
 * after all were found. Return 0 for EOF, 1 for all requested tokens found, or
 * a negative errno on failure. Only successful scans prove missing tokens
 * absent. Use a current epoll alias, not a watched target's reused numeric fd.
 * Kernel ep_show_fdinfo prints each registration's data as hexadecimal.
 */
static int syscall_scan_epoll_registrations_locked(
    int epfd, uint64_t token, struct syscall_tracked_fd_object *object,
    size_t remaining) {
  if (epfd < 0)
    return -EBADF;
  char _path[64] = "/proc/thread-self/fdinfo/";
  size_t _len = sizeof("/proc/thread-self/fdinfo/") - 1;
  char _digits[10];
  size_t _nr_digits = 0;
  unsigned int _fd = epfd;
  do {
    _digits[_nr_digits++] = '0' + _fd % 10;
    _fd /= 10;
  } while (_fd);
  while (_nr_digits)
    _path[_len++] = _digits[--_nr_digits];
  _path[_len] = '\0';
  const int _input =
      syscall_raw_openat(AT_FDCWD, _path, O_RDONLY | O_CLOEXEC, 0);
  if (_input < 0)
    return _input;

  enum {
    SYSCALL_PREFIX,
    SYSCALL_SKIP_LINE,
    SYSCALL_FIND_DATA,
    SYSCALL_VAL,
    SYSCALL_TAIL
  } _state = SYSCALL_PREFIX;
  static const char _prefix[] = "tfd:", _key[] = " data:";
  size_t _matched = 0, _hex_digits = 0;
  uint64_t _val = 0;
  int _answer = 0;
  for (;;) {
    char _buf[SYSCALL_EPOLL_FDINFO_BYTES];
    const ssize_t _cnt = syscall_raw_read(_input, _buf, sizeof(_buf));
    if (_cnt == -EINTR)
      continue;
    if (_cnt < 0) {
      _answer = _cnt;
      break;
    }
    if (!_cnt) {
      if (_state == SYSCALL_VAL)
        _answer = _hex_digits ? syscall_match_epoll_registration_locked(
                                    _val, token, object, &remaining)
                              : -EIO;
      else if (_state == SYSCALL_FIND_DATA ||
               (_state == SYSCALL_PREFIX && _matched))
        _answer = -EIO;
      break;
    }
    for (ssize_t i = 0; i < _cnt; ++i) {
      const unsigned char _character = _buf[i];
      if (_character == '\n') {
        if (_state == SYSCALL_VAL) {
          if (!_hex_digits) {
            _answer = -EIO;
            goto done;
          }
          if (syscall_match_epoll_registration_locked(_val, token, object,
                                                      &remaining)) {
            _answer = 1;
            goto done;
          }
        } else if (_state == SYSCALL_FIND_DATA) {
          _answer = -EIO;
          goto done;
        }
        _state = SYSCALL_PREFIX;
        _matched = _hex_digits = 0;
        _val = 0;
        continue;
      }
      if (_state == SYSCALL_PREFIX) {
        if (_character != (unsigned char)_prefix[_matched]) {
          _state = SYSCALL_SKIP_LINE;
          continue;
        }
        if (++_matched == sizeof(_prefix) - 1) {
          _state = SYSCALL_FIND_DATA;
          _matched = 0;
        }
      } else if (_state == SYSCALL_FIND_DATA) {
        if (_character == (unsigned char)_key[_matched]) {
          if (++_matched == sizeof(_key) - 1)
            _state = SYSCALL_VAL;
        } else
          _matched = _character == ' ' ? 1 : 0;
      } else if (_state == SYSCALL_VAL) {
        if (_character == ' ' || _character == '\t') {
          if (!_hex_digits)
            continue;
          if (syscall_match_epoll_registration_locked(_val, token, object,
                                                      &remaining)) {
            _answer = 1;
            goto done;
          }
          _state = SYSCALL_TAIL;
          continue;
        }
        unsigned int _digit;
        if (_character >= '0' && _character <= '9')
          _digit = _character - '0';
        else if (_character >= 'a' && _character <= 'f')
          _digit = _character - 'a' + 10;
        else if (_character >= 'A' && _character <= 'F')
          _digit = _character - 'A' + 10;
        else {
          _answer = -EIO;
          goto done;
        }
        if (++_hex_digits > 2 * sizeof(_val)) {
          _answer = -EIO;
          goto done;
        }
        _val = (_val << 4) | _digit;
      }
    }
  }
done:
  syscall_raw_close(_input);
  return _answer;
}

/*
 * Remove before freeing a committed version or its owning object. Retained
 * versions stay indexed through the matching native-wait scopes.
 */
static void syscall_unindex_epoll_version_locked(
    struct syscall_epoll_event_version *version) {
  log_verify(syscall_epoll_token_capacity && syscall_epoll_token_cnt);
  const size_t _bucket =
      syscall_epoll_token_bucket(version->token, syscall_epoll_token_capacity);
  struct syscall_epoll_event_version **_link =
      &syscall_epoll_token_buckets[_bucket];
  while (*_link && *_link != version)
    _link = &(*_link)->idx_next;
  log_verify(*_link == version);
  *_link = version->idx_next;
  version->idx_next = NULL;
  version->owner = NULL;
  if (!--syscall_epoll_token_cnt) {
    syscall_free_fd_state(syscall_epoll_token_buckets,
                          syscall_epoll_token_capacity *
                              sizeof(*syscall_epoll_token_buckets));
    syscall_epoll_token_buckets = NULL;
    syscall_epoll_token_capacity = 0;
    syscall_epoll_token_shrink_retry = SIZE_MAX;
  }
}

/*
 * Resize once per collection batch. Reserve before exceeding half load and
 * shrink below one eighth; after failed shrink, retry after another halving.
 */
static void syscall_trim_epoll_token_idx_locked(void) {
  if (!syscall_epoll_token_cnt) {
    if (syscall_epoll_token_buckets)
      syscall_free_fd_state(syscall_epoll_token_buckets,
                            syscall_epoll_token_capacity *
                                sizeof(*syscall_epoll_token_buckets));
    syscall_epoll_token_buckets = NULL;
    syscall_epoll_token_capacity = 0;
    syscall_epoll_token_shrink_retry = SIZE_MAX;
    return;
  }
  if (syscall_epoll_token_capacity <= SYSCALL_EPOLL_TOKEN_MIN_BUCKETS ||
      syscall_epoll_token_cnt > syscall_epoll_token_capacity / 8 ||
      syscall_epoll_token_cnt > syscall_epoll_token_shrink_retry)
    return;
  size_t _capacity = SYSCALL_EPOLL_TOKEN_MIN_BUCKETS;
  while (syscall_epoll_token_cnt > _capacity / 2)
    _capacity *= 2;
  if (syscall_resize_epoll_token_idx_locked(_capacity))
    syscall_epoll_token_shrink_retry = syscall_epoll_token_cnt / 2;
  else
    syscall_epoll_token_shrink_retry = SIZE_MAX;
}

static struct syscall_epoll_event_version *syscall_retired_epoll_versions;

/*
 * Link the new version before retiring the old one: retiring the last indexed
 * record may free the bucket allocation reserved for this publication.
 */
static void
syscall_link_epoll_version_locked(struct syscall_tracked_fd_object *owner,
                                  struct syscall_epoll_event_version *version) {
  version->next = owner->versions;
  version->owner_link = &owner->versions;
  if (version->next)
    version->next->owner_link = &version->next;
  owner->versions = version;
  syscall_idx_epoll_version_locked(owner, version);
}

/*
 * Also use for all versions at final object destruction. It removes queued
 * retirement links before returning the stable version storage to the pool.
 */
static void
syscall_free_epoll_version_locked(struct syscall_epoll_event_version *version) {
  if (version->retired_link) {
    *version->retired_link = version->retired_next;
    if (version->retired_next)
      version->retired_next->retired_link = version->retired_link;
  }
  *version->owner_link = version->next;
  if (version->next)
    version->next->owner_link = version->owner_link;
  syscall_unindex_epoll_version_locked(version);
  syscall_free_fd_state(version, sizeof(*version));
}

static void syscall_retire_epoll_version_locked(
    struct syscall_epoll_event_version *version) {
  if (version->retired)
    return;
  version->retired = true;
  version->native_armed = false;
  if (!version->owner->wait_refs && !version->owner->pending_epoll_cnt) {
    syscall_free_epoll_version_locked(version);
    return;
  }
  version->retired_next = syscall_retired_epoll_versions;
  version->retired_link = &syscall_retired_epoll_versions;
  if (version->retired_next)
    version->retired_next->retired_link = &version->retired_next;
  syscall_retired_epoll_versions = version;
}

/*
 * Called after native-wait scopes finish. Old userdata cannot disappear while a
 * syscall may still return its cookie, or while a retained event needs it. This
 * scans only explicitly retired records, not every live registration.
 */
static void syscall_collect_retired_epoll_versions_locked(void) {
  struct syscall_epoll_event_version *_version = syscall_retired_epoll_versions;
  while (_version) {
    struct syscall_epoll_event_version *const _next = _version->retired_next;
    if (!_version->owner->wait_refs && !_version->owner->pending_epoll_cnt)
      syscall_free_epoll_version_locked(_version);
    _version = _next;
  }
  syscall_trim_epoll_token_idx_locked();
}

static int
syscall_resize_epoll_watch_idx_locked(struct syscall_tracked_fd_object *object,
                                      size_t capacity) {
  if (capacity > SIZE_MAX / sizeof(*object->watch_buckets))
    return -ENOMEM;
  struct syscall_tracked_epoll_watch **const _buckets =
      syscall_alloc_fd_state(capacity * sizeof(*_buckets));
  if (!_buckets)
    return -ENOMEM;
  for (struct syscall_tracked_epoll_watch *_watch = object->watches; _watch;
       _watch = _watch->next) {
    const size_t _bucket =
        syscall_epoll_token_bucket((unsigned int)_watch->fd, capacity);
    _watch->idx_next = _buckets[_bucket];
    _buckets[_bucket] = _watch;
  }
  if (object->watch_buckets)
    syscall_free_fd_state(object->watch_buckets,
                          object->watch_capacity *
                              sizeof(*object->watch_buckets));
  object->watch_buckets = _buckets;
  object->watch_capacity = capacity;
  return 0;
}

/*
 * Reserve watch publication before native ctl. ADD always needs a new watch;
 * MOD needs one only when lookup cannot identify an existing registration.
 */
static int syscall_reserve_epoll_watch_idx_locked(
    struct syscall_tracked_fd_object *object) {
  if (object->watch_cnt < object->watch_capacity / 2)
    return 0;
  if (object->watch_capacity > SIZE_MAX / 2)
    return -ENOMEM;
  const size_t _capacity = object->watch_capacity
                               ? object->watch_capacity * 2
                               : SYSCALL_EPOLL_WATCH_MIN_BUCKETS;
  const int _res = syscall_resize_epoll_watch_idx_locked(object, _capacity);
  if (!_res)
    object->watch_shrink_failed = false;
  return _res;
}

static struct syscall_tracked_epoll_watch *syscall_find_epoll_watch_locked(
    const struct syscall_tracked_fd_object *object, int fd,
    const struct syscall_tracked_fd_object *target) {
  if (!object->watch_capacity)
    return NULL;
  const size_t _bucket =
      syscall_epoll_token_bucket((unsigned int)fd, object->watch_capacity);
  struct syscall_tracked_epoll_watch *_found = NULL;
  for (struct syscall_tracked_epoll_watch *_watch =
           object->watch_buckets[_bucket];
       _watch; _watch = _watch->idx_next) {
    if (_watch->fd != fd || _watch->target != target)
      continue;
    /*
     * Ordinary fd reuse can leave several native open-file descriptions with
     * the same recorded fd number. Preserve that ambiguity instead of merging.
     */
    if (_found)
      return NULL;
    _found = _watch;
  }
  return _found;
}

static void
syscall_trim_epoll_watch_idx_locked(struct syscall_tracked_fd_object *object) {
  if (!object->watch_cnt) {
    if (object->watch_buckets)
      syscall_free_fd_state(object->watch_buckets,
                            object->watch_capacity *
                                sizeof(*object->watch_buckets));
    object->watch_buckets = NULL;
    object->watch_capacity = 0;
    object->watch_shrink_failed = false;
    object->watch_shrink_retry = 0;
    return;
  }
  if (object->retired ||
      object->watch_capacity <= SYSCALL_EPOLL_WATCH_MIN_BUCKETS ||
      object->watch_cnt > object->watch_capacity / 8 ||
      (object->watch_shrink_failed &&
       object->watch_cnt > object->watch_shrink_retry))
    return;
  size_t _capacity = SYSCALL_EPOLL_WATCH_MIN_BUCKETS;
  while (object->watch_cnt > _capacity / 2)
    _capacity *= 2;
  if (syscall_resize_epoll_watch_idx_locked(object, _capacity)) {
    object->watch_shrink_failed = true;
    const size_t _retry = object->watch_cnt / 2;
    object->watch_shrink_retry = _retry > UINT32_MAX ? UINT32_MAX : _retry;
  } else
    object->watch_shrink_failed = false;
}

/*
 * Publish the reserved watch after native success and version indexing. The
 * version owns userdata and ONESHOT state; linking requires no allocation.
 */
static void
syscall_link_epoll_watch_locked(struct syscall_tracked_fd_object *owner,
                                struct syscall_tracked_epoll_watch *watch,
                                struct syscall_tracked_fd_object *target,
                                struct syscall_epoll_event_version *version,
                                int fd, uint32_t events) {
  log_verify(owner->watch_cnt < owner->watch_capacity / 2);
  const size_t _bucket =
      syscall_epoll_token_bucket((unsigned int)fd, owner->watch_capacity);
  *watch = (struct syscall_tracked_epoll_watch){
      .next = owner->watches,
      .prev = &owner->watches,
      .target_next = target ? target->incoming_watches : NULL,
      .idx_next = owner->watch_buckets[_bucket],
      .target = target,
      .version = version,
      .events = events,
      .fd = fd};
  if (watch->next)
    watch->next->prev = &watch->next;
  owner->watches = owner->watch_buckets[_bucket] = watch;
  if (target)
    target->incoming_watches = watch;
  ++owner->watch_cnt;
  version->watch = watch;
}

/*
 * Unlink before retiring the saved version. A target's final close repeatedly
 * removes incoming_watches at the head, so that expected cleanup is O(degree)
 * and never visits unrelated objects. Arbitrary DEL pays only its target's
 * incoming-chain scan, plus one expected-constant fd hash lookup.
 */
static void
syscall_free_epoll_watch_locked(struct syscall_tracked_epoll_watch *watch) {
  struct syscall_tracked_fd_object *const _owner = watch->version->owner;
  const size_t _bucket = syscall_epoll_token_bucket((unsigned int)watch->fd,
                                                    _owner->watch_capacity);
  struct syscall_tracked_epoll_watch **_idx = &_owner->watch_buckets[_bucket];
  while (*_idx && *_idx != watch)
    _idx = &(*_idx)->idx_next;
  log_verify(*_idx == watch && _owner->watch_cnt);
  *_idx = watch->idx_next;
  *watch->prev = watch->next;
  if (watch->next)
    watch->next->prev = watch->prev;
  if (watch->target) {
    struct syscall_tracked_epoll_watch **_incoming =
        &watch->target->incoming_watches;
    while (*_incoming && *_incoming != watch)
      _incoming = &(*_incoming)->target_next;
    log_verify(*_incoming == watch);
    *_incoming = watch->target_next;
  }
  if (watch->version->watch == watch)
    watch->version->watch = NULL;
  --_owner->watch_cnt;
  syscall_free_fd_state(watch, sizeof(*watch));
}

/*
 * Native close can remove an ordinary target without entering FD emulation.
 * Only revisited fd keys need validation; unrelated ADDs do no procfs I/O. Keep
 * entries when the kernel cannot be queried rather than guessing whether an
 * untracked duplicate still holds the open-file description alive.
 */
static void syscall_prune_ordinary_epoll_watches_locked(
    struct syscall_tracked_fd_object *object, int epfd, int fd,
    const struct syscall_epoll_event_version *keep) {
  if (!object->watch_capacity)
    return;
  const size_t _bucket =
      syscall_epoll_token_bucket((unsigned int)fd, object->watch_capacity);
  struct syscall_tracked_epoll_watch *_watch = object->watch_buckets[_bucket];
  while (_watch) {
    struct syscall_tracked_epoll_watch *const _next = _watch->idx_next;
    if (!_watch->target && _watch->fd == fd && _watch->version != keep &&
        syscall_scan_epoll_registrations_locked(epfd, _watch->version->token,
                                                NULL, 0) == 0) {
      struct syscall_epoll_event_version *const _version = _watch->version;
      syscall_free_epoll_watch_locked(_watch);
      syscall_retire_epoll_version_locked(_version);
    }
    _watch = _next;
  }
}

static void syscall_clear_pending_epoll_events_locked(
    struct syscall_tracked_fd_object *object) {
  if (object->pending_epoll_events)
    syscall_free_fd_state(object->pending_epoll_events,
                          object->pending_epoll_capacity *
                              sizeof(struct syscall_epoll_pending_event));
  atomic_fetch_sub_explicit(&syscall_nr_pending_epoll_events,
                            object->pending_epoll_cnt, memory_order_relaxed);
  object->pending_epoll_events = NULL;
  object->pending_epoll_cnt = 0;
  object->pending_epoll_capacity = 0;
  object->pending_epoll_seq = 0;
}

static void
syscall_release_fd_object_locked(struct syscall_tracked_fd_object *object) {
  if (object->aliases)
    return;
  if (!object->retired) {
    object->retired = true;
    if (object->kind == SYSCALL_TRACKED_SIGNALFD)
      atomic_fetch_sub_explicit(&syscall_nr_signalfds, 1, memory_order_relaxed);
    /*
     * Closing a target invalidates only watches linked to that target.
     */
    while (object->incoming_watches) {
      struct syscall_epoll_event_version *const _version =
          object->incoming_watches->version;
      struct syscall_tracked_fd_object *const _owner = _version->owner;
      syscall_free_epoll_watch_locked(object->incoming_watches);
      syscall_trim_epoll_watch_idx_locked(_owner);
      syscall_retire_epoll_version_locked(_version);
    }
    if (object->wait_refs) {
      object->next = syscall_retired_fd_objects;
      syscall_retired_fd_objects = object;
      return;
    }
  }
  if (object->wait_refs)
    return;
  while (object->watches)
    syscall_free_epoll_watch_locked(object->watches);
  syscall_trim_epoll_watch_idx_locked(object);
  while (object->versions)
    syscall_free_epoll_version_locked(object->versions);
  syscall_clear_pending_epoll_events_locked(object);
  syscall_free_fd_state(object, sizeof(*object));
}

static void syscall_collect_epoll_objects_locked(void) {
  struct syscall_tracked_fd_object **_link = &syscall_retired_fd_objects;
  while (*_link) {
    struct syscall_tracked_fd_object *const _object = *_link;
    if (_object->wait_refs) {
      _link = &_object->next;
      continue;
    }
    *_link = _object->next;
    syscall_release_fd_object_locked(_object);
  }
  syscall_collect_retired_epoll_versions_locked();
}

static void
syscall_link_fd_alias_locked(struct syscall_tracked_fd_table *table,
                             struct syscall_tracked_fd_alias *alias) {
  alias->next = table->aliases;
  alias->prev = &table->aliases;
  if (alias->next)
    alias->next->prev = &alias->next;
  table->aliases = alias;
}

static void
syscall_unlink_fd_alias_locked(struct syscall_tracked_fd_alias *alias) {
  *alias->prev = alias->next;
  if (alias->next)
    alias->next->prev = alias->prev;
}

static void syscall_close_fd_locked(int fd) {
  struct syscall_tracked_fd_alias *const _alias =
      syscall_find_fd_alias_locked(fd);
  if (!_alias)
    return;
  struct syscall_tracked_fd_object *const _object = _alias->object;
  syscall_publish_fd_idx_locked(syscall_fd_thread_owner->table, fd, NULL);
  syscall_unlink_fd_alias_locked(_alias);
  syscall_free_fd_state(_alias, sizeof(*_alias));
  --_object->aliases;
  syscall_release_fd_object_locked(_object);
}

/*
 * Called only after successful native duplication. Existing tracked targets
 * retain their alias node. Reserve a node before the syscall only when its
 * source is tracked and its destination has no tracked alias yet.
 */
static void
syscall_duplicate_fd_locked(struct syscall_tracked_fd_alias *reservation,
                            int oldfd, int newfd) {
  struct syscall_tracked_fd_object *const _object =
      syscall_find_fd_locked(oldfd);
  struct syscall_tracked_fd_alias *const _target =
      syscall_find_fd_alias_locked(newfd);
  if (oldfd == newfd || (_target && _target->object == _object)) {
    if (reservation)
      syscall_free_fd_state(reservation, sizeof(*reservation));
    return;
  }
  if (!_object) {
    syscall_close_fd_locked(newfd);
    if (reservation)
      syscall_free_fd_state(reservation, sizeof(*reservation));
    return;
  }
  /*
   * Pin the new binding before retiring watches of the replaced target.
   */
  syscall_publish_epoll_scope_binding_locked(newfd, _object);
  ++_object->aliases;
  if (_target) {
    struct syscall_tracked_fd_object *const _old_object = _target->object;
    _target->object = _object;
    syscall_publish_fd_idx_locked(syscall_fd_thread_owner->table, newfd,
                                  _target);
    --_old_object->aliases;
    syscall_release_fd_object_locked(_old_object);
    if (reservation)
      syscall_free_fd_state(reservation, sizeof(*reservation));
    return;
  }
  log_verify(reservation);
  *reservation =
      (struct syscall_tracked_fd_alias){.object = _object, .fd = newfd};
  syscall_link_fd_alias_locked(syscall_fd_thread_owner->table, reservation);
  syscall_publish_fd_idx_locked(syscall_fd_thread_owner->table, newfd,
                                reservation);
}

static void syscall_register_fd_locked(int fd,
                                       enum syscall_tracked_fd_kind kind,
                                       struct syscall_tracked_fd_object *object,
                                       struct syscall_tracked_fd_alias *alias) {
  *object = (struct syscall_tracked_fd_object){.kind = kind, .aliases = 1};
  *alias = (struct syscall_tracked_fd_alias){.object = object, .fd = fd};
  syscall_link_fd_alias_locked(syscall_fd_thread_owner->table, alias);
  syscall_publish_fd_idx_locked(syscall_fd_thread_owner->table, fd, alias);
  syscall_publish_epoll_scope_binding_locked(fd, object);
  if (kind == SYSCALL_TRACKED_SIGNALFD)
    atomic_fetch_add_explicit(&syscall_nr_signalfds, 1, memory_order_relaxed);
}

static int syscall_emulate_signalfd4(int fd, const kernel_sigset_t *mask,
                                     size_t size, int flags) {
  if (size != sizeof(kernel_sigset_t) ||
      (flags & ~(SFD_CLOEXEC | SFD_NONBLOCK)))
    return -EINVAL;
  kernel_sigset_t _mask;
  int _res = syscall_copy_user_mem(&_mask, mask, sizeof(_mask));
  if (_res)
    return _res;

  kernel_sigset_t _entry;
  sig_lock_rt_sigaction(&_entry);
  struct syscall_tracked_fd_object *_object = syscall_find_fd_locked(fd);
  struct syscall_tracked_fd_alias *_alias = NULL;
  const bool _untracked = !_object;
  if (_untracked) {
    _res = syscall_reserve_fd_idx_locked();
    if (_res) {
      sig_unlock_rt_sigaction(&_entry);
      return _res;
    }
    _object = syscall_alloc_fd_state(sizeof(*_object));
    _alias = syscall_alloc_fd_state(sizeof(*_alias));
    if (!_object || !_alias) {
      _res = -ENOMEM;
      goto failed;
    }
  }
  _res = syscall_raw_signalfd4(fd, &_mask, sizeof(_mask), flags);
  if (_res < 0)
    goto failed;
  if (_untracked)
    syscall_register_fd_locked(_res, SYSCALL_TRACKED_SIGNALFD, _object, _alias);
  _object->mask =
      _mask.__val[0] & ~(1UL << (SIGKILL - 1)) & ~(1UL << (SIGSTOP - 1));
  sig_unlock_rt_sigaction(&_entry);
  return _res;

failed:
  if (_untracked) {
    if (_object)
      syscall_free_fd_state(_object, sizeof(*_object));
    if (_alias)
      syscall_free_fd_state(_alias, sizeof(*_alias));
  }
  sig_unlock_rt_sigaction(&_entry);
  return _res;
}

/*
 * Convert the active siginfo union instead of leaking unrelated union bytes.
 */
static struct signalfd_siginfo syscall_signalfd_info(const siginfo_t *info) {
  struct signalfd_siginfo _res = {.ssi_signo = info->si_signo,
                                  .ssi_errno = info->si_errno,
                                  .ssi_code = info->si_code};
  if (info->si_code == SI_TIMER) {
    _res.ssi_tid = info->si_timerid;
    _res.ssi_overrun = info->si_overrun;
    _res.ssi_ptr = (uintptr_t)info->si_value.sival_ptr;
    _res.ssi_int = info->si_value.sival_int;
  } else if (info->si_code == SI_SIGIO ||
             (info->si_signo == SIGIO && info->si_code > 0 &&
              info->si_code <= POLL_HUP)) {
    _res.ssi_band = info->si_band;
    _res.ssi_fd = info->si_fd;
  } else if (info->si_signo == SIGCHLD && info->si_code > 0 &&
             info->si_code <= CLD_CONTINUED) {
    _res.ssi_pid = info->si_pid;
    _res.ssi_uid = info->si_uid;
    _res.ssi_status = info->si_status;
    _res.ssi_utime = info->si_utime;
    _res.ssi_stime = info->si_stime;
  } else if (info->si_code > 0 && info->si_code != SI_KERNEL &&
             (info->si_signo == SIGILL || info->si_signo == SIGFPE ||
              info->si_signo == SIGSEGV || info->si_signo == SIGBUS ||
              info->si_signo == SIGTRAP)) {
    _res.ssi_addr = (uintptr_t)info->si_addr;
    if (info->si_signo == SIGBUS &&
        (info->si_code == BUS_MCEERR_AR || info->si_code == BUS_MCEERR_AO))
      _res.ssi_addr_lsb = info->si_addr_lsb;
  } else if (info->si_signo == SIGSYS && info->si_code > 0 &&
             info->si_code != SI_KERNEL) {
    _res.ssi_call_addr = (uintptr_t)info->si_call_addr;
    _res.ssi_syscall = info->si_syscall;
    _res.ssi_arch = info->si_arch;
  } else {
    _res.ssi_pid = info->si_pid;
    _res.ssi_uid = info->si_uid;
    if (info->si_code < 0) {
      _res.ssi_ptr = (uintptr_t)info->si_value.sival_ptr;
      _res.ssi_int = info->si_value.sival_int;
    }
  }
  return _res;
}

/*
 * Native signalfd reads may consume an inhibited arrival before a signal frame
 * is built. Preserve its public siginfo fields when sending it through the
 * hook.
 */
static siginfo_t
syscall_native_signalfd_info(const struct signalfd_siginfo *record) {
  siginfo_t _info = {.si_signo = record->ssi_signo,
                     .si_errno = record->ssi_errno,
                     .si_code = record->ssi_code};
  if (_info.si_code == SI_TIMER) {
    _info.si_timerid = record->ssi_tid;
    _info.si_overrun = record->ssi_overrun;
    _info.si_value.sival_ptr = (void *)(uintptr_t)record->ssi_ptr;
  } else if (_info.si_code == SI_SIGIO ||
             (_info.si_signo == SIGIO && _info.si_code > 0 &&
              _info.si_code <= POLL_HUP)) {
    _info.si_band = record->ssi_band;
    _info.si_fd = record->ssi_fd;
  } else if (_info.si_signo == SIGCHLD && _info.si_code > 0 &&
             _info.si_code <= CLD_CONTINUED) {
    _info.si_pid = record->ssi_pid;
    _info.si_uid = record->ssi_uid;
    _info.si_status = record->ssi_status;
    _info.si_utime = record->ssi_utime;
    _info.si_stime = record->ssi_stime;
  } else if (_info.si_signo == SIGSYS && _info.si_code > 0 &&
             _info.si_code != SI_KERNEL) {
    _info.si_call_addr = (void *)(uintptr_t)record->ssi_call_addr;
    _info.si_syscall = record->ssi_syscall;
    _info.si_arch = record->ssi_arch;
  } else if (_info.si_code > 0 && _info.si_code != SI_KERNEL &&
             (_info.si_signo == SIGILL || _info.si_signo == SIGFPE ||
              _info.si_signo == SIGSEGV || _info.si_signo == SIGBUS ||
              _info.si_signo == SIGTRAP)) {
    _info.si_addr = (void *)(uintptr_t)record->ssi_addr;
    if (_info.si_signo == SIGBUS &&
        (_info.si_code == BUS_MCEERR_AR || _info.si_code == BUS_MCEERR_AO))
      _info.si_addr_lsb = record->ssi_addr_lsb;
  } else {
    _info.si_pid = record->ssi_pid;
    _info.si_uid = record->ssi_uid;
    if (_info.si_code < 0)
      _info.si_value.sival_ptr = (void *)(uintptr_t)record->ssi_ptr;
  }
  return _info;
}

static unsigned long
syscall_fd_ready_locked(const struct syscall_tracked_fd_object *object,
                        unsigned int depth) {
  if (!object)
    return 0;
  unsigned long _seq =
      object->pending_epoll_cnt ? object->pending_epoll_seq : 0;
  if (object->kind == SYSCALL_TRACKED_SIGNALFD) {
    const unsigned long _pending = sig_pending_seq(object->mask);
    return _pending > _seq ? _pending : _seq;
  }
  if (depth >= 5)
    return false; // The kernel rejects deeper epoll nesting.
  for (struct syscall_tracked_epoll_watch *_watch = object->watches; _watch;
       _watch = _watch->next) {
    if (!_watch->target || !_watch->version->armed ||
        !(_watch->events & (EPOLLIN | EPOLLRDNORM)))
      continue;
    const unsigned long _ready =
        syscall_fd_ready_locked(_watch->target, depth + 1);
    if (!_ready)
      _watch->edge_seq = 0;
    if (_ready && (!(_watch->events & EPOLLET) || _ready != _watch->edge_seq) &&
        _ready > _seq)
      _seq = _ready;
  }
  return _seq;
}

/*
 * Call after queue consumption/discard so ET registrations rearm on a drain.
 */
void syscall_refresh_fd_edges_locked(void) {
  for (size_t i = 0; i < syscall_epoll_token_capacity; ++i)
    for (struct syscall_epoll_event_version *_version =
             syscall_epoll_token_buckets[i];
         _version; _version = _version->idx_next)
      if (_version->watch &&
          !syscall_fd_ready_locked(_version->watch->target, 0))
        _version->watch->edge_seq = 0;
}

static int syscall_emulate_epoll_ctl(int epfd, int op, int fd,
                                     struct epoll_event *event, long *res) {
  if (!syscall_is_tracked_fd(epfd, false))
    return 1;
  kernel_sigset_t _entry;
  sig_lock_rt_sigaction(&_entry);
  struct syscall_tracked_fd_object *const _epoll = syscall_find_fd_locked(epfd);
  struct syscall_tracked_fd_object *const _target = syscall_find_fd_locked(fd);
  if (!_epoll || _epoll->kind != SYSCALL_TRACKED_EPOLL) {
    sig_unlock_rt_sigaction(&_entry);
    return 1;
  }
  struct epoll_event _event = {0};
  int _res = 0;
  struct syscall_tracked_epoll_watch *_reserved = NULL;
  struct syscall_epoll_event_version *_new_version = NULL;
  /*
   * ADD creates a distinct registration; MOD/DEL preserve fd-reuse ambiguity.
   */
  struct syscall_tracked_epoll_watch *const _found =
      op == EPOLL_CTL_ADD
          ? NULL
          : syscall_find_epoll_watch_locked(_epoll, fd, _target);
  struct syscall_epoll_event_version *const _old_version =
      _found ? _found->version : NULL;
  if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
    _res = syscall_copy_user_mem(&_event, event, sizeof(_event));
    if (_res)
      goto done;
  }
  if (op == EPOLL_CTL_ADD || (op == EPOLL_CTL_MOD && !_found)) {
    _res = syscall_reserve_epoll_watch_idx_locked(_epoll);
    if (_res)
      goto done;
    _reserved = syscall_alloc_fd_state(sizeof(*_reserved));
    if (!_reserved) {
      _res = -ENOMEM;
      goto done;
    }
  }
  struct syscall_epoll_event_version *_version = NULL;
  if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
    /*
     * Reusing a token must not let an older in-flight ONESHOT event consume a
     * new arm. Ordinary fd reuse also cannot prove registration identity.
     */
    if (op == EPOLL_CTL_MOD && _found &&
        (!_epoll->wait_refs ||
         (!_old_version->oneshot && !(_event.events & EPOLLONESHOT) &&
          _found->events == _event.events)) &&
        !_epoll->pending_epoll_cnt &&
        _found->version->data.u64 == _event.data.u64 &&
        (_target ||
         (!_found->version->oneshot && !(_event.events & EPOLLONESHOT))))
      _version = _found->version;
    else {
      if (syscall_next_epoll_token == UINT64_MAX) {
        _res = -EOVERFLOW;
        goto done;
      }
      _new_version = syscall_alloc_fd_state(sizeof(*_new_version));
      if (!_new_version) {
        _res = -ENOMEM;
        goto done;
      }
      _res = syscall_reserve_epoll_version_idx_locked();
      if (_res)
        goto done;
      _new_version->token = ++syscall_next_epoll_token;
      _version = _new_version;
    }
  }
  struct epoll_event _native = _event;
  if (_version)
    _native.data.u64 = _version->token;
  _res = syscall_raw_epoll_ctl(epfd, op, fd, &_native);
  if (!_res) {
    if (_version) {
      _version->data = _event.data;
      _version->oneshot = !!(_event.events & EPOLLONESHOT);
      _version->armed = _version->native_armed = true;
      if (_new_version) {
        syscall_link_epoll_version_locked(_epoll, _new_version);
        _new_version = NULL;
      }
    }
    if (_reserved) {
      syscall_link_epoll_watch_locked(_epoll, _reserved, _target, _version, fd,
                                      _event.events);
      _reserved = NULL;
    } else if (op == EPOLL_CTL_MOD && _found) {
      _found->events = _event.events;
      _found->version = _version;
      _version->watch = _found;
      _found->edge_seq = 0;
    } else if (op == EPOLL_CTL_DEL && _found)
      syscall_free_epoll_watch_locked(_found);
    if (_old_version && (op == EPOLL_CTL_DEL ||
                         (op == EPOLL_CTL_MOD && _old_version != _version))) {
      _old_version->watch = NULL;
      syscall_retire_epoll_version_locked(_old_version);
    }
    if (!_target)
      syscall_prune_ordinary_epoll_watches_locked(_epoll, epfd, fd, _version);
  }
done:
  if (_reserved)
    syscall_free_fd_state(_reserved, sizeof(*_reserved));
  if (_new_version)
    syscall_free_fd_state(_new_version, sizeof(*_new_version));
  syscall_trim_epoll_watch_idx_locked(_epoll);
  syscall_trim_epoll_token_idx_locked();
  sig_unlock_rt_sigaction(&_entry);
  *res = _res;
  return 0;
}

/*
 * Peek software events into local output; commit delivered edges and ONESHOT
 * state only after successful user copy. An observed drain may clear a stale
 * edge marker during either pass.
 */
static int syscall_epoll_events_locked(int epfd, struct epoll_event *events,
                                       int cnt, bool commit) {
  struct syscall_tracked_fd_object *const _epoll = syscall_find_fd_locked(epfd);
  if (!_epoll || _epoll->kind != SYSCALL_TRACKED_EPOLL)
    return 0;
  int _written = 0;
  for (struct syscall_tracked_epoll_watch *_watch = _epoll->watches;
       _watch && _written < cnt; _watch = _watch->next) {
    if (!_watch->target || !_watch->version->armed ||
        !(_watch->events & (EPOLLIN | EPOLLRDNORM)))
      continue;
    const unsigned long _ready = syscall_fd_ready_locked(_watch->target, 0);
    if (!_ready)
      _watch->edge_seq = 0;
    if (!_ready || ((_watch->events & EPOLLET) && _ready == _watch->edge_seq))
      continue;
    events[_written++] =
        (struct epoll_event){.events = _watch->events & (EPOLLIN | EPOLLRDNORM),
                             .data = _watch->version->data};
    if (commit) {
      _watch->edge_seq = _ready;
      if (_watch->events & EPOLLONESHOT) {
        _watch->version->armed = false;
        if (syscall_find_fd_locked(_watch->fd) == _watch->target) {
          struct epoll_event _disabled = {.events = EPOLLONESHOT,
                                          .data.u64 = _watch->version->token};
          if (!syscall_raw_epoll_ctl(epfd, EPOLL_CTL_MOD, _watch->fd,
                                     &_disabled))
            _watch->version->native_armed = false;
        }
      }
    }
  }
  if (commit)
    syscall_refresh_fd_edges_locked();
  return _written;
}

/*
 * Kernel event data is an immutable version token until translation. Explicit
 * MOD/DEL invalidates queued readiness from the previous registration version;
 * an accepted ONESHOT remains deliverable even though version->armed is false.
 */

static int syscall_prune_pending_epoll_events_locked(
    struct syscall_tracked_fd_object *object) {
  size_t _verify = 0;
  for (size_t i = 0; i < object->pending_epoll_cnt; ++i) {
    const struct syscall_epoll_pending_event *const _event =
        &object->pending_epoll_events[i];
    struct syscall_epoll_event_version *const _version =
        syscall_find_epoll_version_locked(_event->token, NULL);
    if (_version && _version->owner == object && _version->watch &&
        !_version->watch->target && _event->verify_registration) {
      _version->fdinfo_registered = false;
      if (!_version->fdinfo_requested) {
        _version->fdinfo_requested = true;
        ++_verify;
      }
    }
  }
  int _err = 0;
  if (_verify) {
    int _epfd = -1;
    for (const struct syscall_tracked_fd_alias *_alias = syscall_tracked_fds;
         _alias; _alias = _alias->next)
      if (_alias->object == object) {
        _epfd = _alias->fd;
        break;
      }
    _err = syscall_scan_epoll_registrations_locked(_epfd, 0, object, _verify);
    if (_err > 0)
      _err = 0;
  }
  size_t _kept = 0;
  for (size_t i = 0; i < object->pending_epoll_cnt; ++i) {
    const struct syscall_epoll_pending_event _event =
        object->pending_epoll_events[i];
    struct syscall_epoll_event_version *const _version =
        syscall_find_epoll_version_locked(_event.token, NULL);
    const struct syscall_tracked_epoll_watch *const _watch =
        _version && _version->owner == object ? _version->watch : NULL;
    bool _current = _event.token == 0 || _watch;
    if (_current && _watch && !_watch->target && _event.verify_registration &&
        !_err && !_version->fdinfo_registered)
      _current = false;
    if (_version && _version->owner == object)
      _version->fdinfo_requested = false;
    if (_current)
      object->pending_epoll_events[_kept++] = _event;
  }
  if (_kept != object->pending_epoll_cnt)
    atomic_fetch_sub_explicit(&syscall_nr_pending_epoll_events,
                              object->pending_epoll_cnt - _kept,
                              memory_order_release);
  object->pending_epoll_cnt = _kept;
  if (!_kept)
    object->pending_epoll_seq = 0;
  return _err;
}

/*
 * Drain/filter native readiness only for a retained batch or a logically
 * disarmed ONESHOT that can still wake in the kernel, including descendants.
 */
static bool syscall_epoll_needs_filter_locked(
    const struct syscall_tracked_fd_object *object, unsigned int depth) {
  if (object->kind != SYSCALL_TRACKED_EPOLL)
    return false;
  if (object->pending_epoll_cnt)
    return true;
  for (const struct syscall_tracked_epoll_watch *_watch = object->watches;
       _watch; _watch = _watch->next) {
    if (_watch->version && _watch->version->oneshot &&
        !_watch->version->armed && _watch->version->native_armed)
      return true;
    if (depth < 5 && _watch->target &&
        _watch->target->kind == SYSCALL_TRACKED_EPOLL &&
        syscall_epoll_needs_filter_locked(_watch->target, depth + 1))
      return true;
  }
  return false;
}

static __always_inline int
syscall_raw_epoll_pwait_zero(int epfd, struct epoll_event *events, int cnt) {
  return util_syscall_no_intercept(SYS_epoll_pwait, (long)epfd, events,
                                   (long)cnt, 0L, &sig_fset, sizeof(sig_fset));
}

static int syscall_reserve_pending_epoll_events_locked(
    struct syscall_tracked_fd_object *object, size_t additional) {
  const size_t _needed = object->pending_epoll_cnt + additional;
  if (_needed <= object->pending_epoll_capacity)
    return 0;
  const size_t _capacity =
      _needed < SYSCALL_EPOLL_EVENT_BATCH ? SYSCALL_EPOLL_EVENT_BATCH : _needed;
  struct syscall_epoll_pending_event *const _events =
      syscall_alloc_fd_state(_capacity * sizeof(*_events));
  if (!_events)
    return -ENOMEM;
  if (object->pending_epoll_events) {
    __builtin_memcpy(_events, object->pending_epoll_events,
                     object->pending_epoll_cnt * sizeof(*_events));
    syscall_free_fd_state(object->pending_epoll_events,
                          object->pending_epoll_capacity * sizeof(*_events));
  }
  object->pending_epoll_events = _events;
  object->pending_epoll_capacity = _capacity;
  return 0;
}

static void syscall_append_pending_epoll_events_locked(
    struct syscall_tracked_fd_object *object, const struct epoll_event *events,
    size_t cnt, bool verify) {
  for (size_t i = 0; i < cnt; ++i) {
    const uint64_t _token = events[i].data.u64;
    object->pending_epoll_events[object->pending_epoll_cnt++] =
        (struct syscall_epoll_pending_event){
            .event = events[i],
            .token =
                syscall_find_epoll_version_locked(_token, NULL) ? _token : 0,
            .verify_registration = verify};
  }
  if (cnt) {
    object->pending_epoll_seq = ++sig_deferred_seq;
    atomic_fetch_add_explicit(&syscall_nr_pending_epoll_events, cnt,
                              memory_order_release);
  }
}

/*
 * Native acceptance and nested readiness sanitation call each other.
 */
static int syscall_accept_native_epoll_events_locked(struct epoll_event *events,
                                                     int cnt);

/*
 * This zero-time drain runs with fset and the metadata lock held. Reserve the
 * persistent batch before consuming kernel events, so allocation failure loses
 * nothing. Stop after any valid batch: a level-triggered FD can remain ready
 * forever, so draining until the kernel returns zero would not terminate.
 */
static int syscall_drain_native_epoll_readiness_locked(
    struct syscall_tracked_fd_object *object, int epfd) {
  const int _err = syscall_reserve_pending_epoll_events_locked(
      object, SYSCALL_EPOLL_EVENT_BATCH);
  if (_err)
    return _err;
  struct epoll_event _events[SYSCALL_EPOLL_PENDING_BYTES /
                             sizeof(struct syscall_epoll_pending_event)];
  for (;;) {
    const int _cnt = syscall_raw_epoll_pwait_zero(
        epfd, _events, sizeof(_events) / sizeof(_events[0]));
    if (_cnt <= 0)
      return _cnt;
    const int _accepted =
        syscall_accept_native_epoll_events_locked(_events, _cnt);
    if (_accepted) {
      syscall_append_pending_epoll_events_locked(object, _events, _accepted,
                                                 true);
      return 1;
    }
    /*
     * Rejected ONESHOT entries are natively disarmed; stale child epolls have
     * been sanitized. Continue until an empty or deliverable batch.
     */
  }
}

/*
 * Sanitize children before draining a parent: its EPOLLIN may reflect only a
 * child's stale ONESHOT entry. Bound recursion by the kernel nesting limit.
 */
static int
syscall_sanitize_epoll_tree_locked(struct syscall_tracked_fd_object *object,
                                   int epfd, unsigned int depth) {
  const int _err = syscall_prune_pending_epoll_events_locked(object);
  if (_err)
    return _err;
  if (object->pending_epoll_cnt)
    return 1;
  for (struct syscall_tracked_epoll_watch *_watch = object->watches;
       depth < 5 && _watch; _watch = _watch->next) {
    if (!_watch->target || _watch->target->kind != SYSCALL_TRACKED_EPOLL ||
        !syscall_epoll_needs_filter_locked(_watch->target, depth + 1))
      continue;
    int _child_fd = -1;
    for (const struct syscall_tracked_fd_alias *_alias = syscall_tracked_fds;
         _alias; _alias = _alias->next)
      if (_alias->object == _watch->target) {
        _child_fd = _alias->fd;
        break;
      }
    if (_child_fd >= 0) {
      const int _res = syscall_sanitize_epoll_tree_locked(_watch->target,
                                                          _child_fd, depth + 1);
      if (_res < 0)
        return _res;
    }
    /*
     * If a nested epoll has no alias in this fd table, it cannot be drained
     * through an FD without introducing private aliases. Preserve its native
     * event rather than guessing that it contains only stale readiness.
     */
  }
  return syscall_drain_native_epoll_readiness_locked(object, epfd);
}

/*
 * Call only when epoll_needs_filter_locked reports true. A zero return means
 * that native read readiness may be cleared; fd_ready_locked can still add
 * virtual readiness, including buffered events in child epolls.
 */
static int syscall_sanitize_epoll_readiness_locked(
    struct syscall_tracked_fd_object *object, int epfd) {
  return syscall_sanitize_epoll_tree_locked(object, epfd, 0);
}

/*
 * Resolve scalar tokens under the lock. A native-wait scope retains versions
 * across an unlocked wait, even if its epfd is closed or reused. Unrecognized
 * cookies pass through as registrations created outside interception.
 */
static int syscall_accept_native_epoll_events_locked(struct epoll_event *events,
                                                     int cnt) {
  int _written = 0;
  for (int i = 0; i < cnt; ++i) {
    struct syscall_tracked_fd_object *_owner = NULL;
    struct syscall_epoll_event_version *const _version =
        syscall_find_epoll_version_locked(events[i].data.u64, &_owner);
    if (_version && (!_version->oneshot || _version->armed) &&
        (events[i].events & (EPOLLIN | EPOLLRDNORM))) {
      struct syscall_tracked_epoll_watch *const _watch = _version->watch;
      if (_watch && _watch->target &&
          _watch->target->kind == SYSCALL_TRACKED_EPOLL &&
          syscall_epoll_needs_filter_locked(_watch->target, 0)) {
        int _child_fd = -1, _owner_fd = -1;
        for (const struct syscall_tracked_fd_alias *_alias =
                 syscall_tracked_fds;
             _alias; _alias = _alias->next) {
          if (_alias->object == _watch->target)
            _child_fd = _alias->fd;
          if (_alias->object == _owner)
            _owner_fd = _alias->fd;
        }
        if (_child_fd >= 0 &&
            syscall_sanitize_epoll_readiness_locked(_watch->target,
                                                    _child_fd) == 0 &&
            !syscall_fd_ready_locked(_watch->target, 0)) {
          events[i].events &= ~(EPOLLIN | EPOLLRDNORM);
          if (!events[i].events) {
            /*
             * A stale child must not consume its parent's logical ONESHOT.
             * Restore the native arm when its registration is addressable.
             */
            if (_version->oneshot) {
              _version->native_armed = false;
              if (_owner_fd >= 0 &&
                  syscall_find_fd_locked(_watch->fd) == _watch->target) {
                struct epoll_event _native = {.events = _watch->events};
                _native.data.u64 = _version->token;
                if (!syscall_raw_epoll_ctl(_owner_fd, EPOLL_CTL_MOD, _watch->fd,
                                           &_native))
                  _version->native_armed = true;
              }
            }
            continue;
          }
        }
      }
    }
    if (_version && _version->oneshot) {
      _version->native_armed = false;
      if (!_version->armed)
        continue;
      _version->armed = false;
    }
    struct epoll_event _event = events[i];
    events[_written++] = _event;
  }
  return _written;
}

/*
 * Peek into local output and commit only the successfully copied prefix. Native
 * acceptance already handled ONESHOT state for this retained batch; repeating
 * it here would discard accepted events.
 */
static int
syscall_pending_epoll_events_locked(struct syscall_tracked_fd_object *object,
                                    struct epoll_event *events, int cnt,
                                    bool commit) {
  if (!commit) {
    const int _err = syscall_prune_pending_epoll_events_locked(object);
    if (_err)
      return _err;
  }
  const size_t _cnt = object->pending_epoll_cnt < (size_t)cnt
                          ? object->pending_epoll_cnt
                          : (size_t)cnt;
  if (!commit) {
    for (size_t i = 0; i < _cnt; ++i) {
      events[i] = object->pending_epoll_events[i].event;
      if (object->pending_epoll_events[i].token) {
        struct syscall_tracked_fd_object *_owner = NULL;
        const struct syscall_epoll_event_version *const _version =
            syscall_find_epoll_version_locked(
                object->pending_epoll_events[i].token, &_owner);
        if (_version)
          events[i].data = _version->data;
      }
    }
  } else if (_cnt) {
    object->pending_epoll_cnt -= _cnt;
    memmove(object->pending_epoll_events, object->pending_epoll_events + _cnt,
            object->pending_epoll_cnt *
                sizeof(struct syscall_epoll_pending_event));
    atomic_fetch_sub_explicit(&syscall_nr_pending_epoll_events, _cnt,
                              memory_order_release);
    if (!object->pending_epoll_cnt)
      object->pending_epoll_seq = 0;
  }
  return _cnt;
}

static int syscall_add_poll_readiness_locked(struct pollfd *fds, nfds_t cnt) {
  int _ready = 0;
  for (nfds_t i = 0; i < cnt; ++i) {
    struct syscall_tracked_fd_object *const _object =
        syscall_find_fd_locked(fds[i].fd);
    if (_object && _object->kind == SYSCALL_TRACKED_EPOLL &&
        syscall_epoll_needs_filter_locked(_object, 0)) {
      const int _res =
          syscall_sanitize_epoll_readiness_locked(_object, fds[i].fd);
      if (_res < 0)
        return _res;
      if (!_res)
        fds[i].revents &= ~(POLLIN | POLLRDNORM);
    }
    if (_object && (fds[i].events & (POLLIN | POLLRDNORM)) &&
        !(fds[i].revents & POLLNVAL) && syscall_fd_ready_locked(_object, 0))
      fds[i].revents |= fds[i].events & (POLLIN | POLLRDNORM);
    _ready += fds[i].revents != 0;
  }
  return _ready;
}

static __always_inline int syscall_raw_dup(int oldfd) {
  return util_syscall_no_intercept(SYS_dup, oldfd);
}

static __always_inline int syscall_raw_dup2(int oldfd, int newfd) {
  return util_syscall_no_intercept(SYS_dup2, oldfd, newfd);
}

static __always_inline int syscall_raw_dup3(int oldfd, int newfd, int flags) {
  return util_syscall_no_intercept(SYS_dup3, oldfd, newfd, flags);
}

static __always_inline long syscall_raw_fcntl(int fd, int cmd, long arg) {
  return util_syscall_no_intercept(SYS_fcntl, fd, cmd, arg);
}

static __always_inline int syscall_raw_epoll_create(int size) {
  return util_syscall_no_intercept(SYS_epoll_create, size);
}

static __always_inline int syscall_raw_epoll_create1(int flags) {
  return util_syscall_no_intercept(SYS_epoll_create1, flags);
}

static int syscall_raw_close_range(unsigned int first, unsigned int last,
                                   int flags) {
  const int fd = syscall_fd_thread_owner->table->hook_fd;
  if (fd >= 0 && first <= (unsigned int)fd && (unsigned int)fd <= last &&
      !(flags & ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC))) {
    /* Keep the registry's descriptor in each copied file table. Perform any
     * requested unshare on the first native call, before closing either side.
     * UINT_MAX cannot name a Linux FD and provides a no-op range if needed. */
    const int err = util_syscall_no_intercept(
        SYS_close_range, first < (unsigned int)fd ? first : UINT_MAX,
        first < (unsigned int)fd ? (unsigned int)fd - 1 : UINT_MAX, flags);
    if (err || (unsigned int)fd == last)
      return err;
    return util_syscall_no_intercept(SYS_close_range, (unsigned int)fd + 1,
                                     last, flags & ~CLOSE_RANGE_UNSHARE);
  }
  return util_syscall_no_intercept(SYS_close_range, first, last, flags);
}

static __always_inline int syscall_raw_unshare(unsigned long flags) {
  return util_syscall_no_intercept(SYS_unshare, flags);
}

static struct syscall_tracked_fd_owner *
syscall_find_fd_owner_locked(pid_t thread) {
  for (struct syscall_tracked_fd_owner *_owner = syscall_fd_owners; _owner;
       _owner = _owner->next)
    if (_owner->thread == thread)
      return _owner;
  return NULL;
}

/*
 * Build the new aliases and index together before clone/unshare can commit.
 * Sharing object references is intentional; sharing source alias nodes is not.
 */
static struct syscall_tracked_fd_table *
syscall_copy_fd_table_locked(const struct syscall_tracked_fd_table *src) {
  struct syscall_tracked_fd_table *const _table =
      syscall_alloc_fd_state(sizeof(*_table));
  if (!_table)
    return NULL;
  syscall_init_fd_idx_locked(_table);
  atomic_init(&_table->hook_fd, src ? src->hook_fd : hook_backing_fd);
  for (const struct syscall_tracked_fd_alias *_alias = src ? src->aliases
                                                           : NULL;
       _alias; _alias = _alias->next) {
    struct syscall_tracked_fd_alias *const _copy =
        syscall_alloc_fd_state(sizeof(*_copy));
    if (!_copy)
      goto failed;
    if (syscall_reserve_fd_idx_for_fd_locked(_table, _alias->fd)) {
      syscall_free_fd_state(_copy, sizeof(*_copy));
      goto failed;
    }
    *_copy = (struct syscall_tracked_fd_alias){.object = _alias->object,
                                               .fd = _alias->fd};
    ++_copy->object->aliases;
    syscall_link_fd_alias_locked(_table, _copy);
    syscall_publish_fd_idx_locked(_table, _copy->fd, _copy);
  }
  _table->next = syscall_fd_tables;
  syscall_fd_tables = _table;
  return _table;

failed:
  while (_table->aliases) {
    struct syscall_tracked_fd_alias *const _removed = _table->aliases;
    syscall_publish_fd_idx_locked(_table, _removed->fd, NULL);
    syscall_unlink_fd_alias_locked(_removed);
    --_removed->object->aliases;
    syscall_free_fd_state(_removed, sizeof(*_removed));
  }
  syscall_destroy_fd_idx_locked(&_table->idx);
  syscall_free_fd_state(_table, sizeof(*_table));
  return NULL;
}

static void
syscall_discard_fd_table_locked(struct syscall_tracked_fd_table *table) {
  struct syscall_tracked_fd_table **_link = &syscall_fd_tables;
  while (*_link != table)
    _link = &(*_link)->next;
  *_link = table->next;
  /*
   * Use a temporary lookup context while locked; it is not a live owner.
   */
  struct syscall_tracked_fd_owner _temporary = {.table = table};
  struct syscall_tracked_fd_owner *const _saved = syscall_fd_thread_owner;
  syscall_fd_thread_owner = &_temporary;
  while (syscall_tracked_fds)
    syscall_close_fd_locked(syscall_tracked_fds->fd);
  syscall_fd_thread_owner = _saved;
  syscall_destroy_fd_idx_locked(&table->idx);
  syscall_free_fd_state(table, sizeof(*table));
}

static void
syscall_clear_saved_select_sets_locked(struct syscall_tracked_fd_owner *owner) {
  while (owner->saved_select_sets) {
    struct syscall_saved_select_sets *const _saved = owner->saved_select_sets;
    owner->saved_select_sets = _saved->next;
    internal_raw_munmap(_saved, _saved->mapping_size);
  }
}

static void
syscall_remove_fd_owner_locked(struct syscall_tracked_fd_owner *owner) {
  syscall_clear_epoll_scopes_owner_locked(owner);
  syscall_clear_saved_select_sets_locked(owner);
  struct syscall_tracked_fd_table *const _table = owner->table;
  owner->table = NULL;
  if (_table && !--_table->owners)
    syscall_discard_fd_table_locked(_table);
  syscall_collect_epoll_objects_locked();
  struct syscall_tracked_fd_owner **_link = &syscall_fd_owners;
  while (*_link != owner)
    _link = &(*_link)->next;
  *_link = owner->next;
  syscall_free_fd_state(owner, sizeof(*owner));
}

/*
 * Prepare once under the signal lock before enabling interception.
 */
static int syscall_init_fd_table_locked(void) {
  struct syscall_tracked_fd_owner *const _owner =
      syscall_alloc_fd_state(sizeof(*_owner));
  if (!_owner)
    return -(errno ? errno : ENOMEM);
  struct syscall_tracked_fd_table *const _table =
      syscall_copy_fd_table_locked(NULL);
  if (!_table) {
    const int _err = errno ? errno : ENOMEM;
    syscall_free_fd_state(_owner, sizeof(*_owner));
    return -_err;
  }
  *_owner = (struct syscall_tracked_fd_owner){
      .table = _table, .thread = _overlaysys_syscall_self_tid};
  _table->owners = 1;
  syscall_fd_thread_owner = syscall_fd_owners = _owner;
  return 0;
}

/*
 * Reserve before native clone so its successful parent callback cannot fail
 * allocation, and so a creator cannot release its table before child startup. A
 * new thread inherits the logical mask and effective dispatch eligibility
 * without inheriting the parent's callback frame. Creating a thread inside a
 * callback suppresses user syscall-hook dispatch in that child.
 */
static int syscall_prepare_fd_clone_locked(unsigned long flags) {
  if (!(flags & CLONE_VM))
    return 0;
  struct syscall_tracked_fd_owner *const _owner =
      syscall_alloc_fd_state(sizeof(*_owner));
  if (!_owner)
    return -ENOMEM;
  struct syscall_tracked_fd_table *const _table =
      flags & CLONE_FILES
          ? syscall_fd_thread_owner->table
          : syscall_copy_fd_table_locked(syscall_fd_thread_owner->table);
  if (!_table) {
    syscall_free_fd_state(_owner, sizeof(*_owner));
    return -ENOMEM;
  }
  *_owner = (struct syscall_tracked_fd_owner){
      .next = syscall_fd_owners,
      .table = _table,
      .clone_wrapper_requested =
          atomic_load_explicit(&syscall_hook_state, memory_order_relaxed) ==
              1 &&
          !atomic_load_explicit(&syscall_user_cb_active, memory_order_relaxed),
      .clone_mask = sig_logical_sigmask};
  ++_table->owners;
  syscall_fd_owners = syscall_fd_clone_owner = _owner;
  return 0;
}

/*
 * Publish the child's owner before unlocking. A shared child cannot attach or
 * exit while the parent's retained action lock still protects this record.
 */
static void syscall_finish_fd_clone_locked(long child_thread) {
  struct syscall_tracked_fd_owner *const _reserved = syscall_fd_clone_owner;
  syscall_fd_clone_owner = NULL;
  if (!_reserved)
    return;
  if (child_thread > 0)
    _reserved->thread = child_thread;
  else
    syscall_remove_fd_owner_locked(_reserved);
}

/*
 * exit hook: call under the signal lock before unmapping TLS-owned resources.
 */
static void syscall_exit_fd_thread_locked(void) {
  if (!syscall_fd_thread_owner)
    return;
  syscall_remove_fd_owner_locked(syscall_fd_thread_owner);
  syscall_fd_thread_owner = NULL;
}

/*
 * A private child keeps only the caller's file table. Preserve suspended waits
 * only for a copied-stack continuation. MAP_PRIVATE metadata cleanup cannot
 * alter the parent's tables or scopes.
 */
static void syscall_reset_fd_fork_locked(bool continuation) {
  struct syscall_tracked_fd_owner *const _current = syscall_fd_thread_owner;
  struct syscall_tracked_fd_table *const _table = _current->table;
  if (!continuation) {
    syscall_clear_epoll_scopes_owner_locked(_current);
    syscall_clear_saved_select_sets_locked(_current);
  }
  struct syscall_saved_select_sets *const _saved_select =
      _current->saved_select_sets;
  struct syscall_epoll_wait_scope *const _saved_scopes = _current->epoll_scopes;
  struct syscall_tracked_fd_owner *_owner = syscall_fd_owners;
  while (_owner) {
    struct syscall_tracked_fd_owner *const _next = _owner->next;
    if (_owner != _current) {
      syscall_clear_epoll_scopes_owner_locked(_owner);
      syscall_clear_saved_select_sets_locked(_owner);
      syscall_free_fd_state(_owner, sizeof(*_owner));
    }
    _owner = _next;
  }
  *_current =
      (struct syscall_tracked_fd_owner){.table = _table,
                                        .thread = _overlaysys_syscall_self_tid,
                                        .epoll_scopes = _saved_scopes,
                                        .saved_select_sets = _saved_select};
  _table->owners = 1;
  syscall_fd_owners = _current;
  syscall_fd_clone_owner = NULL;
  struct syscall_tracked_fd_table *_other = syscall_fd_tables;
  while (_other) {
    struct syscall_tracked_fd_table *const _next = _other->next;
    if (_other != _table)
      syscall_discard_fd_table_locked(_other);
    _other = _next;
  }
  syscall_collect_epoll_objects_locked();
}

static void syscall_close_fd_range_locked(unsigned int first,
                                          unsigned int last) {
  struct syscall_tracked_fd_alias *_alias = syscall_tracked_fds;
  while (_alias) {
    struct syscall_tracked_fd_alias *const _next = _alias->next;
    if ((unsigned int)_alias->fd >= first && (unsigned int)_alias->fd <= last)
      syscall_close_fd_locked(_alias->fd);
    _alias = _next;
  }
}

/*
 * Handle table separation before close_range's CLOEXEC fast path. The API
 * requires synchronous callers: a signal callback must not replace the table
 * that an interrupted lock-free classifier is reading.
 */
static int syscall_emulate_fd_unshare(long num, long a, long b, long c,
                                      long *restrict res) {
  if ((num == SYS_unshare && !(a & CLONE_FILES)) ||
      (num == SYS_close_range && !(c & CLOSE_RANGE_UNSHARE)))
    return 1;
  kernel_sigset_t _entry;
  sig_lock_rt_sigaction(&_entry);
  struct syscall_tracked_fd_table *const _old = syscall_fd_thread_owner->table;
  struct syscall_tracked_fd_table *_new = _old;
  /*
   * A private table keeps the same bindings after native unshare; only shared
   * metadata needs a copy. This also avoids allocation on no-op unshares.
   */
  if (_old->owners > 1) {
    *res = syscall_reserve_epoll_scope_table_move_locked();
    if (*res) {
      sig_unlock_rt_sigaction(&_entry);
      return 0;
    }
    _new = syscall_copy_fd_table_locked(_old);
    if (!_new) {
      *res = -ENOMEM;
      sig_unlock_rt_sigaction(&_entry);
      return 0;
    }
  }
  *res = num == SYS_unshare ? syscall_raw_unshare(a)
                            : syscall_raw_close_range(a, b, c);
  if (*res < 0) {
    if (_new != _old)
      syscall_discard_fd_table_locked(_new);
  } else {
    if (_new != _old) {
      _new->owners = 1;
      syscall_fd_thread_owner->table = _new;
      syscall_refresh_epoll_scope_table_locked();
      --_old->owners;
    }
    if (num == SYS_close_range && !(c & CLOSE_RANGE_CLOEXEC))
      syscall_close_fd_range_locked(a, b);
  }
  sig_unlock_rt_sigaction(&_entry);
  return 0;
}

static int syscall_emulate_fd_op(long num, long a, long b, long c,
                                 long *restrict res) {
  const int hook_fd = atomic_load_explicit(
      &syscall_fd_thread_owner->table->hook_fd, memory_order_relaxed);
  const bool hook_src = hook_fd >= 0 && (int)a == hook_fd;
  /*
   * F_SETLKW and other potentially blocking operations must not hold the signal
   * lock. Native status flags are shared by all tracked aliases.
   */
  if (num == SYS_fcntl && b != F_DUPFD && b != F_DUPFD_CLOEXEC && !hook_src)
    return 1;
  if ((num == SYS_dup2 || num == SYS_dup3) && (int)a == (int)b && !hook_src)
    return 1;
  if (((num == SYS_dup2 || num == SYS_dup3) && (int)b < 0) ||
      (num == SYS_dup3 && ((int)c & ~O_CLOEXEC)) ||
      (num == SYS_fcntl && (int)c < 0) ||
      (num == SYS_epoll_create && (int)a <= 0) ||
      (num == SYS_epoll_create1 && ((int)a & ~EPOLL_CLOEXEC)))
    return 1;
  /* A currently untracked target can become the backing FD during relocation.
   * Keep destructive operations locked through classification and execution. */
  if (num != SYS_epoll_create && num != SYS_epoll_create1 && num != SYS_close &&
      num != SYS_close_range && num != SYS_dup2 && num != SYS_dup3 &&
      !syscall_is_tracked_fd(a, false))
    return 1;

  if (num == SYS_close_range) {
    /*
     * CLOEXEC leaves aliases intact; UNSHARE uses emulate_fd_unshare instead.
     */
    if (c != 0 || (unsigned int)a > (unsigned int)b)
      return 1;
  }

  kernel_sigset_t _entry;
  sig_lock_rt_sigaction(&_entry);
  struct syscall_tracked_fd_alias *_alias = NULL;
  struct syscall_tracked_fd_object *_object = NULL;
  long _res;
  const bool _create = num == SYS_epoll_create || num == SYS_epoll_create1;
  const bool _duplicate =
      num == SYS_dup || num == SYS_dup2 || num == SYS_dup3 || num == SYS_fcntl;
  const bool _src_tracked = syscall_find_fd_locked(a) != NULL;
  const bool _fixed_target = num == SYS_dup2 || num == SYS_dup3;
  const int _hook_fd = syscall_fd_thread_owner->table->hook_fd;
  const bool _hook_target =
      _fixed_target && _hook_fd >= 0 && (int)b == _hook_fd;
  int _moved_hook_fd = -1;
  if (!_create && num != SYS_close_range && _hook_fd >= 0 &&
      (int)a == _hook_fd) {
    _res = -EBADF;
    goto done;
  }
  struct syscall_tracked_fd_alias *const _target =
      _fixed_target ? syscall_find_fd_alias_locked((int)b) : NULL;
  const bool _affected = _create || _src_tracked || _fixed_target ||
                         num == SYS_close || num == SYS_close_range;
  if (!_affected) {
    sig_unlock_rt_sigaction(&_entry);
    return 1;
  }
  if (_create || (_duplicate && _src_tracked)) {
    _res = syscall_reserve_epoll_scope_bindings_locked(
        _fixed_target ? (int)b : -1,
        _create ? NULL : syscall_find_fd_locked(a));
    if (_res)
      goto done;
  }
  if (_create || (_duplicate && _src_tracked && !_target)) {
    _res = _fixed_target ? syscall_reserve_fd_idx_for_fd_locked(
                               syscall_fd_thread_owner->table, (int)b)
                         : syscall_reserve_fd_idx_locked();
    if (_res)
      goto done;
  }
  if (_create) {
    _object = syscall_alloc_fd_state(sizeof(*_object));
    _alias = syscall_alloc_fd_state(sizeof(*_alias));
    if (!_object || !_alias) {
      _res = -ENOMEM;
      goto done;
    }
  } else if (_duplicate && _src_tracked && !_target) {
    _alias = syscall_alloc_fd_state(sizeof(*_alias));
    if (!_alias) {
      _res = -ENOMEM;
      goto done;
    }
  }

  if (_hook_target) {
    _res = syscall_raw_fcntl(a, F_GETFD, 0);
    if (_res < 0)
      goto done;
    _res = syscall_raw_fcntl(_hook_fd, F_DUPFD_CLOEXEC, 0);
    if (_res < 0)
      goto done;
    _moved_hook_fd = _res;
  }
  switch (num) {
  case SYS_close:
    _res = syscall_raw_close(a);
    /*
     * Linux releases the descriptor before reporting close-time I/O errors or
     * EINTR. Do not discard metadata for a rejected syscall (e.g. EPERM from
     * seccomp), which never entered close in the kernel.
     */
    if (_res >= 0 || _res == -EINTR || _res == -EIO || _res == -ENOSPC ||
        _res == -EDQUOT)
      syscall_close_fd_locked(a);
    break;
  case SYS_dup:
    _res = syscall_raw_dup(a);
    break;
  case SYS_dup2:
    _res = syscall_raw_dup2(a, b);
    break;
  case SYS_dup3:
    _res = syscall_raw_dup3(a, b, c);
    break;
  case SYS_fcntl:
    _res = syscall_raw_fcntl(a, b, c);
    break;
  case SYS_epoll_create:
    _res = syscall_raw_epoll_create(a);
    break;
  case SYS_epoll_create1:
    _res = syscall_raw_epoll_create1(a);
    break;
  case SYS_close_range:
    _res = syscall_raw_close_range(a, b, c);
    if (!_res)
      syscall_close_fd_range_locked(a, b);
    break;
  default:
    _res = -ENOSYS;
    break;
  }
  if (_moved_hook_fd >= 0) {
    if (_res < 0)
      syscall_raw_close(_moved_hook_fd);
    else
      atomic_store_explicit(&syscall_fd_thread_owner->table->hook_fd,
                            _moved_hook_fd, memory_order_relaxed);
  }
  if (_res >= 0 && _create) {
    syscall_register_fd_locked(_res, SYSCALL_TRACKED_EPOLL, _object, _alias);
    _object = NULL;
    _alias = NULL;
  } else if (_res >= 0 && _duplicate) {
    syscall_duplicate_fd_locked(_alias, a, _res);
    _alias = NULL;
  }
done:
  if (_object)
    syscall_free_fd_state(_object, sizeof(*_object));
  if (_alias)
    syscall_free_fd_state(_alias, sizeof(*_alias));
  syscall_trim_epoll_scope_refs_locked();
  sig_unlock_rt_sigaction(&_entry);
  *res = _res;
  return 0;
}

/*
 * Use the vDSO for internal timeout bookkeeping. Fall back to the raw syscall
 * when its entry is unavailable or returns ENOSYS; propagate other errors.
 */
static __always_inline int syscall_monotonic_time(struct timespec *time) {
  if (syscall_vdso_clock_gettime) {
    const int _res = syscall_vdso_clock_gettime(CLOCK_MONOTONIC, time);
    if (_res != -ENOSYS)
      return _res;
  }
  return util_syscall_no_intercept(SYS_clock_gettime, CLOCK_MONOTONIC, time);
}

/*
 * A zero deadline is the sentinel for an initially zero timeout; it requires
 * neither clock sampling nor a timeout write-back.
 */
struct timespec syscall_wait_deadline(struct timespec timeout) {
  if (!timeout.tv_sec && !timeout.tv_nsec)
    return timeout;
  struct timespec _now;
  log_verify(!patcher_syscall_err_code(syscall_monotonic_time(&_now)));
  if (timeout.tv_sec >= LONG_MAX - _now.tv_sec)
    return (struct timespec){.tv_sec = LONG_MAX, .tv_nsec = 999999999};
  _now.tv_sec += timeout.tv_sec;
  _now.tv_nsec += timeout.tv_nsec;
  if (_now.tv_nsec >= 1000000000) {
    ++_now.tv_sec;
    _now.tv_nsec -= 1000000000;
  }
  return _now;
}

struct timespec syscall_wait_remaining(struct timespec deadline) {
  if (!deadline.tv_sec && !deadline.tv_nsec)
    return deadline;
  struct timespec _now;
  log_verify(!patcher_syscall_err_code(syscall_monotonic_time(&_now)));
  if (_now.tv_sec > deadline.tv_sec ||
      (_now.tv_sec == deadline.tv_sec && _now.tv_nsec >= deadline.tv_nsec))
    return (struct timespec){0};
  deadline.tv_sec -= _now.tv_sec;
  deadline.tv_nsec -= _now.tv_nsec;
  if (deadline.tv_nsec < 0) {
    --deadline.tv_sec;
    deadline.tv_nsec += 1000000000;
  }
  return deadline;
}

struct syscall_wait_select_interest {
  int fd;
};

struct syscall_wait_bufs {
  long num;
  void *mapping, *user_output;
  size_t mapping_size, cnt;
  int epfd, virtual_events;
};

static __always_inline int syscall_raw_getrlimit(int resource,
                                                 struct rlimit *limit) {
  return util_syscall_no_intercept(SYS_getrlimit, resource, limit);
}

/*
 * The private-pipe fallback in syscall_copy_user_mem accepts PIPE_BUF-sized
 * copies. Keep larger poll arrays valid under the same sandbox contract.
 */
static int syscall_copy_wait_buf(void *dest, const void *src, size_t size) {
  while (size) {
    const size_t _part = size < PIPE_BUF ? size : PIPE_BUF;
    const int _err = syscall_copy_user_mem(dest, src, _part);
    if (_err)
      return _err;
    dest = (char *)dest + _part;
    src = (const char *)src + _part;
    size -= _part;
  }
  return 0;
}

/*
 * FDSize is the kernel fdtable capacity, unlike RLIMIT_NOFILE. Optional procfs
 * access avoids copying a huge user-requested nfds which native select would
 * clamp. On unavailable procfs, ordinary valid caller-owned sets still work.
 */
static int syscall_select_fdtable_limit(int requested) {
  const int _fd = syscall_raw_openat(AT_FDCWD, "/proc/thread-self/status",
                                     O_RDONLY | O_CLOEXEC, 0);
  if (_fd < 0)
    return requested;
  char _status[SYSCALL_SELECT_STATUS_BYTES];
  const ssize_t _len = syscall_raw_read(_fd, _status, sizeof(_status) - 1);
  syscall_raw_close(_fd);
  if (_len <= 0)
    return requested;
  _status[_len] = '\0';
  const char *_val = strstr(_status, "\nFDSize:");
  if (!_val)
    return requested;
  _val += sizeof("\nFDSize:") - 1;
  while (*_val == ' ' || *_val == '\t')
    ++_val;
  if (*_val < '0' || *_val > '9')
    return requested;
  unsigned int _limit = 0;
  while (*_val >= '0' && *_val <= '9') {
    const unsigned int _digit = (unsigned int)(*_val++ - '0');
    if (_limit > ((unsigned int)INT_MAX - _digit) / 10)
      return requested;
    _limit = _limit * 10 + _digit;
  }
  return _limit && _limit < (unsigned int)requested ? (int)_limit : requested;
}

/*
 * Each fresh native attempt starts with all original inputs, including write
 * and exception sets which a positive result may have cleared before filtering
 * removes the only stale read event. Clamp the native nfds too: concurrent
 * fdtable growth must not make the kernel read past the owned snapshots.
 */
static void
syscall_restore_saved_select_sets(struct syscall_saved_select_sets *saved,
                                  long args[6]) {
  args[0] = saved->nfds;
  for (size_t i = 0; i < 3; ++i) {
    if (!saved->user_output[i]) {
      args[i + 1] = 0;
      continue;
    }
    void *const _working = (char *)saved->sets + (3 + i) * saved->set_bytes;
    memcpy(_working, (char *)saved->sets + i * saved->set_bytes,
           saved->set_bytes);
    args[i + 1] = (long)_working;
  }
}

/*
 * Return 1 with an owned snapshot, 0 when no tracked epoll is selected, or a
 * raw negative error. Called with the action/FD metadata lock held.
 */
static int
syscall_save_select_sets_locked(long args[6],
                                struct syscall_saved_select_sets **output) {
  *output = NULL;
  const int _requested = args[0];
  if (_requested <= 0 || !args[1] || !syscall_fd_thread_owner)
    return 0;
  bool _needed = false;
  for (const struct syscall_tracked_fd_alias *_alias = syscall_tracked_fds;
       _alias; _alias = _alias->next) {
    if (_alias->object->kind != SYSCALL_TRACKED_EPOLL || _alias->fd < 0 ||
        _alias->fd >= _requested)
      continue;
    const size_t _off = (size_t)_alias->fd /
                        (CHAR_BIT * sizeof(unsigned long)) *
                        sizeof(unsigned long);
    if ((uintptr_t)args[1] > UINTPTR_MAX - _off)
      return -EFAULT;
    unsigned long _word;
    const int _err = syscall_copy_user_mem(
        &_word, (const void *)((uintptr_t)args[1] + _off), sizeof(_word));
    if (_err)
      return _err;
    if (_word & (1UL << (_alias->fd % (CHAR_BIT * sizeof(unsigned long))))) {
      _needed = true;
      break;
    }
  }
  if (!_needed)
    return 0;

  const int _nfds = syscall_select_fdtable_limit(_requested);
  const size_t _bytes = ((size_t)_nfds + CHAR_BIT * sizeof(unsigned long) - 1) /
                        (CHAR_BIT * sizeof(unsigned long)) *
                        sizeof(unsigned long);
  if (_bytes > (SIZE_MAX - sizeof(struct syscall_saved_select_sets)) / 6)
    return -ENOMEM;
  const size_t _size = sizeof(struct syscall_saved_select_sets) + _bytes * 6;
  struct syscall_saved_select_sets *const _saved = internal_raw_mmap(
      NULL, _size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (patcher_syscall_err_code((long)_saved))
    return (long)_saved;
  *_saved = (struct syscall_saved_select_sets){
      .mapping_size = _size, .set_bytes = _bytes, .nfds = _nfds};
  for (size_t i = 0; i < 3; ++i) {
    _saved->user_output[i] = (void *)args[i + 1];
    if (!_saved->user_output[i])
      continue;
    const int _err = syscall_copy_wait_buf((char *)_saved->sets + i * _bytes,
                                           _saved->user_output[i], _bytes);
    if (_err) {
      internal_raw_munmap(_saved, _size);
      return _err;
    }
  }
  _saved->next = syscall_fd_thread_owner->saved_select_sets;
  syscall_fd_thread_owner->saved_select_sets = _saved;
  *output = _saved;
  syscall_restore_saved_select_sets(_saved, args);
  return 1;
}

/*
 * Copy back completed results; native wait errors leave the original sets
 * untouched. A copy error may still leave a successfully written prefix.
 */
static long
syscall_finish_saved_select_sets(const struct syscall_saved_select_sets *saved,
                                 long res) {
  if (res < 0)
    return res;
  for (size_t i = 0; i < 3; ++i) {
    if (!saved->user_output[i])
      continue;
    const int _err = syscall_copy_wait_buf(saved->user_output[i],
                                           (const char *)saved->sets +
                                               (3 + i) * saved->set_bytes,
                                           saved->set_bytes);
    if (_err)
      return _err;
  }
  return res;
}

/*
 * Adjust only epoll read bits present in the original request; preserve the
 * native write/exception results while filtering stale readiness.
 */
static long syscall_filter_saved_select_events_locked(
    const struct syscall_saved_select_sets *saved, long args[6], long res) {
  unsigned long *const _read_set = (void *)args[1];
  for (const struct syscall_tracked_fd_alias *_alias = syscall_tracked_fds;
       _alias; _alias = _alias->next) {
    struct syscall_tracked_fd_object *const _object = _alias->object;
    if (_object->kind != SYSCALL_TRACKED_EPOLL || _alias->fd < 0 ||
        _alias->fd >= saved->nfds)
      continue;
    const size_t _idx =
        (unsigned int)_alias->fd / (CHAR_BIT * sizeof(unsigned long));
    const unsigned long _bit =
        1UL << (_alias->fd % (CHAR_BIT * sizeof(unsigned long)));
    if (!(saved->sets[_idx] & _bit))
      continue;
    const bool _native_ready = !!(_read_set[_idx] & _bit);
    bool _ready = _native_ready;
    if (syscall_epoll_needs_filter_locked(_object, 0)) {
      const int _status =
          syscall_sanitize_epoll_readiness_locked(_object, _alias->fd);
      if (_status < 0) {
        res = _status;
        break;
      }
      if (!_status)
        _ready = false;
    }
    _ready |= syscall_fd_ready_locked(_object, 0) != 0;
    if (_ready)
      _read_set[_idx] |= _bit;
    else
      _read_set[_idx] &= ~_bit;
    res += (int)_ready - (int)_native_ready;
  }
  return res;
}

/*
 * Find the owner-held mapping before dereferencing saved. No pointer into a
 * suspended or abandoned native stack is stored in this list.
 */
static void syscall_release_saved_select_sets_locked(
    struct syscall_tracked_fd_owner *owner,
    struct syscall_saved_select_sets *saved) {
  struct syscall_saved_select_sets **_link = &owner->saved_select_sets;
  while (*_link && *_link != saved)
    _link = &(*_link)->next;
  if (!*_link)
    return;
  *_link = saved->next;
  internal_raw_munmap(saved, saved->mapping_size);
}

/*
 * Batch the transfer, but report only complete events. Record-sized fallback
 * reads let callers retain the uncopied suffix after a fault.
 */
static long syscall_copy_epoll_events(void *output,
                                      const struct epoll_event *events,
                                      int cnt) {
  if (cnt <= 0)
    return cnt;
  static_assert(SYSCALL_EPOLL_EVENT_BATCH * sizeof(*events) <= PIPE_BUF);
  const size_t _size = (size_t)cnt * sizeof(*events);
  if ((uintptr_t)output > UINTPTR_MAX - (_size - 1))
    return -EFAULT;
  const ssize_t _copied =
      syscall_copy_user_bytes(output, events, _size, sizeof(*events));
  if (_copied < 0)
    return _copied;
  const long _complete = (size_t)_copied / sizeof(*events);
  return _complete ? _complete : -EFAULT;
}

static long syscall_copy_pending_epoll_events_locked(
    struct syscall_tracked_fd_object *object, struct epoll_event *events,
    int cnt, void *output) {
  const int _cnt =
      syscall_pending_epoll_events_locked(object, events, cnt, false);
  if (_cnt < 0)
    return _cnt;
  const long _copied = syscall_copy_epoll_events(output, events, _cnt);
  if (_copied > 0)
    syscall_pending_epoll_events_locked(object, events, _copied, true);
  /*
   * These records will outlive this call; ordinary descriptor closure can
   * remain native because the next peek validates the kernel registration.
   */
  for (size_t i = 0; i < object->pending_epoll_cnt; ++i)
    object->pending_epoll_events[i].verify_registration = true;
  return _copied;
}

/*
 * Save accepted native records with their raw tokens before copying translated
 * userdata to the caller. They remain pending until a complete record is
 * copied, preserving readiness and the uncopied suffix on EFAULT or a partial
 * result.
 *
 * When no older batch needs pruning, translate directly in the native buffer to
 * avoid a second peek and translation pass.
 */
static long syscall_copy_native_epoll_events_locked(
    struct syscall_tracked_fd_object *object, struct epoll_event *events,
    int cnt, int capacity, void *output) {
  if (object->pending_epoll_cnt)
    goto queued;
  for (int i = 0; i < cnt; ++i) {
    struct syscall_tracked_fd_object *_owner = NULL;
    const struct syscall_epoll_event_version *const _version =
        syscall_find_epoll_version_locked(events[i].data.u64, &_owner);
    if (_version && (_owner != object || !_version->watch)) {
      /*
       * Restore the translated prefix to raw tokens, then let the queued path
       * prune retired or foreign versions.
       */
      for (int j = 0; j < i; ++j)
        events[j] = object->pending_epoll_events[j].event;
      goto queued;
    }
    object->pending_epoll_events[i] = (struct syscall_epoll_pending_event){
        .event = events[i],
        .token = _version ? _version->token : 0,
        .verify_registration = true,
    };
    if (_version)
      events[i].data = _version->data;
  }
  if (cnt) {
    object->pending_epoll_cnt = cnt;
    object->pending_epoll_seq = ++sig_deferred_seq;
    atomic_fetch_add_explicit(&syscall_nr_pending_epoll_events, cnt,
                              memory_order_release);
  }
  const long _res = syscall_copy_epoll_events(output, events, cnt);
  const size_t _copied = _res > 0 ? (size_t)_res : 0;
  const size_t _remaining = (size_t)cnt - _copied;
  if (_copied) {
    if (_remaining)
      memmove(object->pending_epoll_events,
              object->pending_epoll_events + _copied,
              _remaining * sizeof(*object->pending_epoll_events));
    object->pending_epoll_cnt = _remaining;
    atomic_fetch_sub_explicit(&syscall_nr_pending_epoll_events, _copied,
                              memory_order_release);
    if (!_remaining)
      object->pending_epoll_seq = 0;
  }
  return _res;

queued:
  syscall_append_pending_epoll_events_locked(object, events, cnt, false);
  return syscall_copy_pending_epoll_events_locked(object, events, capacity,
                                                  output);
}

static void syscall_release_wait_bufs(struct syscall_wait_bufs *bufs) {
  if (bufs->mapping)
    internal_raw_munmap(bufs->mapping, bufs->mapping_size);
  bufs->mapping = NULL;
}

/*
 * Short-lived readiness buffers, created under the action lock. Poll copies its
 * array; select records tracked read interests in the current fd_sets, which
 * may already be owned retry snapshots. Release before a native wait.
 */
static int syscall_init_wait_bufs_locked(struct syscall_wait_bufs *bufs,
                                         long num, long args[6]) {
  *bufs = (struct syscall_wait_bufs){.num = num};
  if (num == SYS_ppoll) {
    const unsigned int _cnt = args[1];
    struct rlimit _limit;
    int _err = syscall_raw_getrlimit(RLIMIT_NOFILE, &_limit);
    if (_err)
      return _err;
    if (_cnt > _limit.rlim_cur)
      return -EINVAL;
    bufs->cnt = _cnt;
    bufs->user_output = (void *)args[0];
    bufs->mapping_size = (size_t)_cnt * sizeof(struct pollfd);
    if (!_cnt)
      return 0;
  } else if (num == SYS_pselect6) {
    const int _nfds = args[0];
    if (_nfds < 0)
      return -EINVAL;
    bufs->user_output = (void *)args[1];
    if (!args[1])
      return 0;
    for (const struct syscall_tracked_fd_alias *_alias = syscall_tracked_fds;
         _alias; _alias = _alias->next)
      if (_alias->fd >= 0 && _alias->fd < _nfds)
        ++bufs->cnt;
    if (!bufs->cnt)
      return 0;
    if (bufs->cnt > SIZE_MAX / sizeof(struct syscall_wait_select_interest))
      return -ENOMEM;
    bufs->mapping_size =
        bufs->cnt * sizeof(struct syscall_wait_select_interest);
  } else if (num == SYS_epoll_pwait || num == SYS_epoll_pwait2) {
    const int _maxevents = args[2];
    if (_maxevents <= 0 ||
        _maxevents > (int)(INT_MAX / sizeof(struct epoll_event)))
      return -EINVAL;
    bufs->epfd = args[0];
    bufs->user_output = (void *)args[1];
    /*
     * maxevents is an upper bound, so one x86 base page is a valid output batch
     * even for a huge request; remaining events stay pending.
     */
    bufs->cnt = (size_t)_maxevents < SYSCALL_EPOLL_EVENT_BATCH
                    ? (size_t)_maxevents
                    : SYSCALL_EPOLL_EVENT_BATCH;
    bufs->mapping_size = bufs->cnt * sizeof(struct epoll_event);
  } else
    return 0;

  bufs->mapping =
      internal_raw_mmap(NULL, bufs->mapping_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (patcher_syscall_err_code((long)bufs->mapping)) {
    const int _err = (long)bufs->mapping;
    bufs->mapping = NULL;
    return _err;
  }
  int _err = 0;
  if (num == SYS_ppoll) {
    _err = syscall_copy_wait_buf(bufs->mapping, bufs->user_output,
                                 bufs->mapping_size);
    if (!_err)
      args[0] = (long)bufs->mapping;
  } else if (num == SYS_pselect6) {
    struct syscall_wait_select_interest *const _interests = bufs->mapping;
    size_t _cnt = 0;
    for (const struct syscall_tracked_fd_alias *_alias = syscall_tracked_fds;
         _alias; _alias = _alias->next) {
      const int _fd = _alias->fd;
      if (_fd < 0 || _fd >= (int)args[0])
        continue;
      const size_t _off =
          (size_t)_fd / (8 * sizeof(unsigned long)) * sizeof(unsigned long);
      unsigned long _word;
      if ((uintptr_t)bufs->user_output > UINTPTR_MAX - _off) {
        _err = -EFAULT;
        break;
      }
      _err = syscall_copy_user_mem(
          &_word, (const char *)bufs->user_output + _off, sizeof(_word));
      if (_err)
        break;
      if (_word & (1UL << (_fd % (8 * sizeof(unsigned long)))))
        _interests[_cnt++].fd = _fd;
    }
    bufs->cnt = _cnt;
  } else {
    args[1] = (long)bufs->mapping;
    args[2] = bufs->cnt;
  }
  if (_err)
    syscall_release_wait_bufs(bufs);
  return _err;
}

/*
 * Prepare virtual readiness before a native attempt. Ready poll/select calls
 * use a zero timeout; an epoll software batch is returned on its own, leaving
 * native events for a later wait.
 */
static int syscall_prepare_wait_bufs_locked(struct syscall_wait_bufs *bufs) {
  if (bufs->num == SYS_ppoll) {
    struct pollfd *const _fds = bufs->mapping;
    for (size_t i = 0; i < bufs->cnt; ++i)
      _fds[i].revents = 0;
    return syscall_add_poll_readiness_locked(_fds, bufs->cnt);
  }
  if (bufs->num == SYS_pselect6) {
    const struct syscall_wait_select_interest *_interests = bufs->mapping;
    int _ready = 0;
    for (size_t i = 0; i < bufs->cnt; ++i) {
      struct syscall_tracked_fd_object *const _object =
          syscall_find_fd_locked(_interests[i].fd);
      if (_object && _object->kind == SYSCALL_TRACKED_EPOLL &&
          syscall_epoll_needs_filter_locked(_object, 0)) {
        const int _res =
            syscall_sanitize_epoll_readiness_locked(_object, _interests[i].fd);
        if (_res < 0)
          return _res;
      }
      _ready += _object && syscall_fd_ready_locked(_object, 0);
    }
    return _ready;
  }
  if (bufs->num == SYS_epoll_pwait || bufs->num == SYS_epoll_pwait2) {
    bufs->virtual_events = syscall_epoll_events_locked(
        bufs->epfd, bufs->mapping, bufs->cnt, false);
    return bufs->virtual_events;
  }
  return 0;
}

/*
 * Called only when the surrounding wait is complete. Negative native results
 * leave user buffers unchanged. The action lock spans collection, user copy,
 * and ET/ONESHOT commit so a failed copy cannot consume a software edge.
 */
static long syscall_finish_wait_bufs_locked(struct syscall_wait_bufs *bufs,
                                            long res) {
  if (res < 0)
    return res;
  if (bufs->num == SYS_ppoll) {
    struct pollfd *const _fds = bufs->mapping;
    res = syscall_add_poll_readiness_locked(_fds, bufs->cnt);
    if (res < 0)
      return res;
    /*
     * Like the kernel, update only revents; fd/events are application inputs.
     */
    for (size_t i = 0; i < bufs->cnt; ++i) {
      const int _err = syscall_copy_user_mem(
          &((struct pollfd *)bufs->user_output)[i].revents, &_fds[i].revents,
          sizeof(_fds[i].revents));
      if (_err)
        return _err;
    }
  } else if (bufs->num == SYS_pselect6) {
    const struct syscall_wait_select_interest *_interests = bufs->mapping;
    for (size_t i = 0; i < bufs->cnt; ++i) {
      const int _fd = _interests[i].fd;
      const struct syscall_tracked_fd_object *const _object =
          syscall_find_fd_locked(_fd);
      if (!_object || !syscall_fd_ready_locked(_object, 0))
        continue;
      const size_t _off =
          (size_t)_fd / (8 * sizeof(unsigned long)) * sizeof(unsigned long);
      void *const _dest = (char *)bufs->user_output + _off;
      unsigned long _word;
      int _err = syscall_copy_user_mem(&_word, _dest, sizeof(_word));
      if (_err)
        return _err;
      const unsigned long _bit = 1UL << (_fd % (8 * sizeof(unsigned long)));
      if (_word & _bit)
        continue;
      _word |= _bit;
      _err = syscall_copy_user_mem(_dest, &_word, sizeof(_word));
      if (_err)
        return _err;
      ++res;
    }
  } else if (bufs->num == SYS_epoll_pwait || bufs->num == SYS_epoll_pwait2) {
    if (bufs->virtual_events)
      res = bufs->virtual_events;
    res = syscall_copy_epoll_events(bufs->user_output, bufs->mapping, res);
    if (res > 0 && bufs->virtual_events)
      syscall_epoll_events_locked(bufs->epfd, bufs->mapping, res, true);
  }
  return res;
}

static long syscall_emulate_masked_wait(long num, long a, long b, long c,
                                        long d, long e, long f) {
  const kernel_sigset_t *_mask = NULL;
  size_t _size = sizeof(kernel_sigset_t);
  struct timespec *_user_timeout = NULL;
  struct timeval *_user_timeval = NULL;
  struct timespec _timeout = {0}, _deadline = {0};
  bool _timed = false;
  if (num == SYS_poll) {
    if ((int)c >= 0) {
      _timeout = (struct timespec){.tv_sec = (int)c / 1000,
                                   .tv_nsec = ((int)c % 1000) * 1000000L};
      _timed = true;
    }
    num = SYS_ppoll;
    c = d = 0;
    e = sizeof(kernel_sigset_t);
  } else if (num == SYS_select) {
    _user_timeval = addr_cast(e);
    if (_user_timeval) {
      struct timeval _val;
      const int _err =
          syscall_copy_user_mem(&_val, _user_timeval, sizeof(_val));
      if (_err)
        return _err;
      if (_val.tv_sec < 0 || _val.tv_usec < 0)
        return -EINVAL;
      if (_val.tv_usec / 1000000 > LONG_MAX - _val.tv_sec)
        _timeout = (struct timespec){.tv_sec = LONG_MAX, .tv_nsec = 999999999};
      else
        _timeout =
            (struct timespec){.tv_sec = _val.tv_sec + _val.tv_usec / 1000000,
                              .tv_nsec = (_val.tv_usec % 1000000) * 1000};
      _timed = true;
    }
    num = SYS_pselect6;
    e = f = 0;
  } else if (num == SYS_epoll_wait) {
    num = SYS_epoll_pwait;
    e = 0;
    f = sizeof(kernel_sigset_t);
  }
  struct wait_call _call = {.num = num, .args = {a, b, c, d, e, f}};
  if (num == SYS_rt_sigsuspend) {
    _mask = addr_cast(a);
    _size = b;
  } else if (num == SYS_ppoll) {
    _mask = addr_cast(d);
    _size = e;
    _user_timeout = addr_cast(c);
  } else if (num == SYS_pselect6) {
    if (f) {
      struct {
        const kernel_sigset_t *set;
        size_t size;
      } _arg;
      const int _err = syscall_copy_user_mem(&_arg, addr_cast(f), sizeof(_arg));
      if (_err)
        return _err;
      _mask = _arg.set;
      _size = _arg.size;
    }
    _user_timeout = addr_cast(e);
  } else {
    _mask = addr_cast(e);
    _size = f;
    if (num == SYS_epoll_pwait) {
      const int _milliseconds = d;
      if (_milliseconds >= 0) {
        _timeout =
            (struct timespec){.tv_sec = _milliseconds / 1000,
                              .tv_nsec = (_milliseconds % 1000) * 1000000L};
        _timed = true;
      }
    } else
      _user_timeout = addr_cast(d);
  }
  if (_user_timeout) {
    const int _err =
        syscall_copy_user_mem(&_timeout, _user_timeout, sizeof(_timeout));
    if (_err)
      return _err;
    if (_timeout.tv_sec < 0 || _timeout.tv_nsec < 0 ||
        _timeout.tv_nsec >= 1000000000)
      return -EINVAL;
    _timed = true;
  }
  if ((_mask || num == SYS_rt_sigsuspend) && _size != sizeof(kernel_sigset_t))
    return -EINVAL;
  if (_mask || num == SYS_rt_sigsuspend) {
    const int _err =
        syscall_copy_user_mem(&_call.temporary, _mask, sizeof(_call.temporary));
    if (_err)
      return _err;
  }
  if (_timed)
    _deadline = syscall_wait_deadline(_timeout);
  kernel_sigset_t _actual;
  sig_lock_rt_sigaction(&_actual);
  sig_sync_logical_sigmask(_actual);
  _call.orig = sig_logical_sigmask;
  if (!_mask)
    _call.temporary = sig_logical_sigmask;
  _call.temporary.__val[0] &=
      ~((1UL << (SIGKILL - 1)) | (1UL << (SIGSTOP - 1)));
  const unsigned long _forwarded = sig_forwarded_sigs;
  struct syscall_saved_select_sets *_saved_select = NULL;
  if (num == SYS_pselect6) {
    const int _err =
        syscall_save_select_sets_locked(_call.args, &_saved_select);
    if (_err < 0) {
      sig_unlock_with_replay(sig_filter_logical_sigmask(), false);
      return _err;
    }
  }
  struct epoll_event *_native_events = NULL;
  void *_epoll_output = NULL;
  if ((num == SYS_epoll_pwait || num == SYS_epoll_pwait2) &&
      syscall_is_tracked_fd(a, false)) {
    if ((int)c <= 0 || (int)c > (int)(INT_MAX / sizeof(struct epoll_event))) {
      sig_unlock_with_replay(sig_filter_logical_sigmask(), false);
      return -EINVAL;
    }
    const size_t _cnt =
        (int)c < SYSCALL_EPOLL_EVENT_BATCH ? (int)c : SYSCALL_EPOLL_EVENT_BATCH;
    _native_events = __builtin_alloca(_cnt * sizeof(*_native_events));
    _epoll_output = (void *)b;
    _call.args[1] = (long)_native_events;
    _call.args[2] = _cnt;
  }
  long _res;
  for (;;) {
    if (sig_has_captured()) {
      _res = -EINTR;
      break;
    }
    if (_saved_select)
      syscall_restore_saved_select_sets(_saved_select, _call.args);
    if (_native_events) {
      struct syscall_tracked_fd_object *const _object =
          syscall_find_fd_locked(a);
      if (_object && _object->kind == SYSCALL_TRACKED_EPOLL) {
        /*
         * A retained batch is validated by copy_pending below. Sanitizing it
         * here would scan the same fdinfo twice without an intervening wait.
         */
        if (!_object->pending_epoll_cnt &&
            syscall_epoll_needs_filter_locked(_object, 0)) {
          _res = syscall_sanitize_epoll_readiness_locked(_object, a);
          if (_res < 0)
            break;
        }
        if (_object->pending_epoll_cnt) {
          _res = syscall_copy_pending_epoll_events_locked(
              _object, _native_events, _call.args[2], _epoll_output);
          if (_res)
            break;
        }
        _res =
            syscall_reserve_pending_epoll_events_locked(_object, _call.args[2]);
        if (_res)
          break;
      }
    }
    /*
     * Resolve virtual readiness with signals blocked, then free temporary
     * buffers before the interruptible wait. Persistent select snapshots and
     * epoll scopes remain owner-held if a handler abandons this call.
     */
    if ((sig_has_pending() &&
         atomic_load_explicit(&syscall_nr_signalfds, memory_order_relaxed)) ||
        ((num == SYS_ppoll || num == SYS_pselect6) &&
         (atomic_load_explicit(&syscall_nr_signalfds, memory_order_relaxed) ||
          atomic_load_explicit(&syscall_nr_pending_epoll_events,
                               memory_order_relaxed)))) {
      long _saved[6];
      __builtin_memcpy(_saved, _call.args, sizeof(_saved));
      struct syscall_wait_bufs _bufs;
      if (_native_events)
        _call.args[1] = (long)_epoll_output;
      _res = syscall_init_wait_bufs_locked(&_bufs, num, _call.args);
      if (_res)
        break;
      const int _ready = syscall_prepare_wait_bufs_locked(&_bufs);
      if (_ready < 0)
        _res = _ready;
      else if (_ready) {
        struct timespec _zero = {0};
        if (num == SYS_ppoll) {
          _call.args[2] = (long)&_zero;
          _call.args[3] = (long)&sig_fset;
          _call.args[4] = sizeof(sig_fset);
          _res = sig_raw_ppoll(&_call);
        } else if (num == SYS_pselect6) {
          const struct {
            const kernel_sigset_t *mask;
            size_t size;
          } _arg = {&sig_fset, sizeof(sig_fset)};
          _call.args[4] = (long)&_zero;
          _call.args[5] = (long)&_arg;
          _res = sig_raw_pselect6(&_call);
        } else
          _res = 0;
        _res = syscall_finish_wait_bufs_locked(&_bufs, _res);
      }
      syscall_release_wait_bufs(&_bufs);
      __builtin_memcpy(_call.args, _saved, sizeof(_saved));
      if (_ready)
        break;
    }
    if (_timed)
      _timeout = syscall_wait_remaining(_deadline);
    if (num == SYS_ppoll)
      _call.args[2] = _timed ? (long)&_timeout : 0;
    else if (num == SYS_pselect6)
      _call.args[4] = _timed ? (long)&_timeout : 0;
    else if (num == SYS_epoll_pwait)
      _call.args[3] =
          !_timed ? -1
          : _timeout.tv_sec > INT_MAX / 1000
              ? INT_MAX
              : _timeout.tv_sec * 1000 + (_timeout.tv_nsec + 999999) / 1000000;
    else if (num == SYS_epoll_pwait2)
      _call.args[3] = _timed ? (long)&_timeout : 0;
    struct syscall_epoll_wait_scope *_epoll_scope = NULL;
    if (_native_events) {
      _res = syscall_begin_epoll_scope_locked((int)a, &_epoll_scope);
      if (_res)
        break;
    }
    _res = sig_run_masked_wait(&_call);
    if (_saved_select && _res > 0) {
      _res = syscall_filter_saved_select_events_locked(_saved_select,
                                                       _call.args, _res);
      if (!_res)
        continue;
    }
    if (num == SYS_ppoll && _res > 0 &&
        (atomic_load_explicit(&syscall_nr_signalfds, memory_order_relaxed) ||
         atomic_load_explicit(&syscall_nr_pending_epoll_events,
                              memory_order_relaxed))) {
      long _saved[6];
      __builtin_memcpy(_saved, _call.args, sizeof(_saved));
      struct syscall_wait_bufs _bufs;
      const int _err = syscall_init_wait_bufs_locked(&_bufs, num, _call.args);
      _res = _err ? _err : syscall_finish_wait_bufs_locked(&_bufs, _res);
      syscall_release_wait_bufs(&_bufs);
      __builtin_memcpy(_call.args, _saved, sizeof(_saved));
      if (!_res)
        continue;
    }
    if (_native_events) {
      bool _retry = false;
      if (_res > 0) {
        struct syscall_tracked_fd_object *_owner = NULL;
        for (long i = 0; i < _res && !_owner; ++i)
          syscall_find_epoll_version_locked(_native_events[i].data.u64,
                                            &_owner);
        if (_owner) {
          const int _err =
              syscall_reserve_pending_epoll_events_locked(_owner, _res);
          if (_err)
            _res = _err;
          else {
            _res =
                syscall_accept_native_epoll_events_locked(_native_events, _res);
            _res = syscall_copy_native_epoll_events_locked(
                _owner, _native_events, _res, _call.args[2], _epoll_output);
            _retry = !_res;
          }
        } else {
          const int _err =
              syscall_copy_wait_buf(_epoll_output, _native_events,
                                    (size_t)_res * sizeof(*_native_events));
          if (_err)
            _res = _err;
        }
      }
      syscall_end_epoll_scope_locked(_epoll_scope);
      syscall_collect_epoll_objects_locked();
      if (_retry)
        continue;
    }
    if (_res != -EINTR || !_call.swallowed || sig_forwarded_sigs != _forwarded)
      break;
  }
  /*
   * Match the kernel's return path for an initially zero timeout: leave the
   * caller's timeout memory untouched.
   */
  const bool _write_timeout = _deadline.tv_sec || _deadline.tv_nsec;
  if (_write_timeout && _user_timeout &&
      (num == SYS_ppoll || num == SYS_pselect6)) {
    _timeout = syscall_wait_remaining(_deadline);
    /*
     * As in the kernel, a failed timeout copy does not replace a completed
     * readiness result or EINTR.
     */
    syscall_copy_user_mem(_user_timeout, &_timeout, sizeof(_timeout));
  }
  if (_write_timeout && _user_timeval) {
    _timeout = syscall_wait_remaining(_deadline);
    const struct timeval _remaining = {.tv_sec = _timeout.tv_sec,
                                       .tv_usec = _timeout.tv_nsec / 1000};
    syscall_copy_user_mem(_user_timeval, &_remaining, sizeof(_remaining));
  }
  if (_saved_select) {
    _res = syscall_finish_saved_select_sets(_saved_select, _res);
    syscall_release_saved_select_sets_locked(syscall_fd_thread_owner,
                                             _saved_select);
  }
  sig_unlock_with_replay(sig_filter_logical_sigmask(), false);
  return _res;
}

/*
 * Ordinary descriptors are forwarded before reading any caller buffers.
 */
static int syscall_emulate_signalfd_read(long num, int fd, void *buf,
                                         size_t cnt, long *res) {
  if (!syscall_is_tracked_fd(fd, true))
    return 1;
  kernel_sigset_t _actual;
  sig_lock_rt_sigaction(&_actual);
  struct syscall_tracked_fd_object *_object = syscall_find_fd_locked(fd);
  if (!_object || _object->kind != SYSCALL_TRACKED_SIGNALFD) {
    sig_unlock_rt_sigaction(&_actual);
    return 1;
  }
  sig_sync_logical_sigmask(_actual);
  struct iovec _single = {.iov_base = buf, .iov_len = cnt};
  struct iovec *_vectors = &_single;
  size_t _nr_vectors = 1, _capacity = cnt;
  *res = 0;
  if (num == SYS_readv) {
    if (cnt > IOV_MAX) {
      *res = -EINVAL;
      goto done;
    }
    if (!cnt)
      goto done;
    /*
     * IOV_MAX bounds the snapshot to 16 KiB on this ABI. Stack storage also
     * disappears if a signal handler abandons a blocking read via longjmp.
     */
    const size_t _size = cnt * sizeof(*_vectors);
    _vectors = __builtin_alloca(_size);
    *res = syscall_copy_wait_buf(_vectors, buf, _size);
    if (*res)
      goto done;
    _nr_vectors = cnt;
    _capacity = 0;
    for (size_t i = 0; i < cnt; ++i) {
      if (_vectors[i].iov_len > SSIZE_MAX - _capacity) {
        *res = -EINVAL;
        goto done;
      }
      _capacity += _vectors[i].iov_len;
    }
    if (!_capacity)
      goto done;
  }
  if (_capacity < sizeof(struct signalfd_siginfo)) {
    *res = -EINVAL;
    goto done;
  }
  size_t _written = 0, _idx = 0, _off = 0;
  while (_capacity - _written >= sizeof(struct signalfd_siginfo)) {
    _object = syscall_find_fd_locked(fd);
    if (!_object || _object->kind != SYSCALL_TRACKED_SIGNALFD) {
      *res = _written ? (long)_written : -EBADF;
      break;
    }
    const long _flags = syscall_raw_fcntl(fd, F_GETFL, 0);
    if (_flags < 0) {
      *res = _written ? (long)_written : _flags;
      break;
    }
    siginfo_t _info = {0};
    int _sig = sig_take_pending_sig(_object->mask, &_info);
    if (_sig == -EINPROGRESS)
      continue;
    if (_sig < 0) {
      *res = _written ? (long)_written : _sig;
      break;
    }
    if (!_sig) {
      if (_written || (_flags & O_NONBLOCK)) {
        *res = _written ? (long)_written : -EAGAIN;
        break;
      }
      if (sig_has_captured()) {
        *res = -EINTR;
        break;
      }
      struct signalfd_siginfo _native;
      struct wait_call _call = {.num = SYS_read,
                                .args = {fd, (long)&_native, sizeof(_native)},
                                .temporary = sig_logical_sigmask,
                                .orig = sig_logical_sigmask,
                                .entry_mask = sig_filter_logical_sigmask(),
                                .read_generation = sig_nonrestart_sigs};
      /*
       * Make the execution boundary live before unmasking, so a hook in the gap
       * before read can divert us back to the queue without losing a wake.
       */
      const int _saved_errno = errno;
      log_verify_err(usersched_unlock_pi(&sig_rt_sigaction_lock,
                                         _overlaysys_syscall_self_tid,
                                         FUTEX_PRIVATE_FLAG));
      errno = _saved_errno;
      atomic_store_explicit(&syscall_internal_emulation, false,
                            memory_order_relaxed);
      const long _res = sig_raw_read_wait(&_call);
      log_verify(_call.entry_restored);
      sig_lock_rt_sigaction(&_actual);
      sig_sync_logical_sigmask(_actual);
      if (_res == -EINTR && _call.intercepted &&
          sig_nonrestart_sigs == _call.read_generation && !sig_has_captured())
        continue;
      if (_res < 0) {
        *res = _res;
        break;
      }
      if (_res != sizeof(_native)) {
        *res = -EIO;
        break;
      }
      _info = syscall_native_signalfd_info(&_native);
      if (_info.si_signo <= 0 || _info.si_signo >= NSIG) {
        *res = -EIO;
        break;
      }
      _sig = sig_proc_native_sig(_info.si_signo, &_info);
      if (_sig == -EINPROGRESS)
        continue;
      if (_sig < 0) {
        *res = _sig;
        break;
      }
    }
    const struct signalfd_siginfo _record = syscall_signalfd_info(&_info);
    size_t _copied = 0;
    while (_copied < sizeof(_record)) {
      while (_idx < _nr_vectors && _off == _vectors[_idx].iov_len) {
        ++_idx;
        _off = 0;
      }
      const size_t _avail = _vectors[_idx].iov_len - _off;
      const size_t _part = _avail < sizeof(_record) - _copied
                               ? _avail
                               : sizeof(_record) - _copied;
      const int _err =
          syscall_copy_user_mem((char *)_vectors[_idx].iov_base + _off,
                                (const char *)&_record + _copied, _part);
      if (_err) {
        *res = _written ? (long)_written : _err;
        goto done;
      }
      _off += _part;
      _copied += _part;
    }
    _written += sizeof(_record);
    *res = _written;
  }
done:
  syscall_refresh_fd_edges_locked();
  sig_unlock_with_replay(sig_filter_logical_sigmask(), false);
  return 0;
}

static __always_inline int syscall_raw_exit(int status) {
  return util_syscall_no_intercept(SYS_exit, status);
}

/*
 * The backend syscall trampoline is a leaf: only its return address and sixth
 * argument use this TLS scratch stack. No C code or lazy PLT lookup runs here.
 */
static thread_local
    __attribute((tls_model("initial-exec"),
                 aligned(16))) unsigned char syscall_exit_stack[128];

static_assert(SYS_munmap == 11 && SYS_exit == 60);
static __attribute((naked, noreturn)) void
syscall_raw_exit_unmap(void *, size_t, int, void *, long (*)(long, ...)) {
  asm volatile("mov %edx, %ebx\n\t"
               "mov %r8, %r12\n\t"
               "mov %rsi, %rdx\n\t"
               "mov %rdi, %rsi\n\t"
               "mov %rcx, %rsp\n\t"
               "and $-16, %rsp\n\t"
               "sub $16, %rsp\n\t"
               "movq $0, (%rsp)\n\t"
               "mov $11, %edi\n\t" // SYS_munmap
               "xor %eax, %eax\n\t"
               "call *%r12\n\t"
               "1:\n\t"
               "mov %ebx, %esi\n\t"
               "mov $60, %edi\n\t" // SYS_exit
               "xor %eax, %eax\n\t"
               "call *%r12\n\t"
               "jmp 1b\n\t");
}

static int syscall_emulate_exit(int status) {
  kernel_sigset_t _exit_mask;
  sig_lock_rt_sigaction(&_exit_mask);
  const bool _on_stack = sig_on_defsigstk(&status);

  /*
   * The action lock already blocks signals: release inactive owned stacks here,
   * or switch to the TLS scratch stack before unmapping the active stack below.
   */
  if (unlikely(sig_defsigstk) && !_on_stack)
    sig_unmap_defsigstk();

  syscall_exit_fd_thread_locked();
  sig_exit_sig_state();
  /*
   * Keep signals blocked until exit so handlers cannot recreate thread state.
   */
  log_verify_err(usersched_unlock_pi(&sig_rt_sigaction_lock,
                                     _overlaysys_syscall_self_tid,
                                     FUTEX_PRIVATE_FLAG));
  if (_on_stack) {
    void *const _mapping = sig_defsigstk;
    sig_defsigstk = NULL;
    syscall_raw_exit_unmap(_mapping, sig_enable_defsigaltstack, status,
                           syscall_exit_stack + sizeof(syscall_exit_stack),
                           util_syscall_no_intercept);
  }
  return syscall_raw_exit(status);
}

/*
 * Hold the action lock and fset across private fork/clone and post-call setup,
 * including parent-side failures. A copied-stack continuation retains active
 * callback state; a new stack inherits the creator's effective dispatch
 * eligibility without that suspended callback frame.
 */
static void syscall_prepare_private_fork_locked(uintptr_t child_tls,
                                                bool continuation) {
  hook_prepare_fork();
  syscall_fork_state.mask = sig_logical_sigmask;
  syscall_fork_state.fd_owner = syscall_fd_thread_owner;
  syscall_fork_state.continuation = continuation;
  syscall_fork_state.cb =
      atomic_load_explicit(&syscall_user_cb_active, memory_order_relaxed);
  syscall_fork_state.hook_state =
      atomic_load_explicit(&syscall_hook_state, memory_order_relaxed);
  syscall_fork_state.errno_state =
      atomic_load_explicit(&syscall_app_errno_state, memory_order_relaxed);
  syscall_fork_state.errno_phase =
      atomic_load_explicit(&syscall_hook_errno_phase, memory_order_relaxed);
  if (!continuation) {
    /*
     * A private clone may start on a new stack too. No parent callback frame
     * will unwind there, but its effective dispatch eligibility still applies.
     */
    syscall_fork_state.hook_state =
        syscall_fork_state.hook_state == 1 && !syscall_fork_state.cb;
    syscall_fork_state.cb = false;
    syscall_fork_state.errno_state = (struct app_errno_state){
        .val = syscall_fork_state.errno_phase == ERRNO_APPLICATION
                   ? errno
                   : syscall_fork_state.errno_state.val};
    syscall_fork_state.errno_phase = ERRNO_APPLICATION;
  }
  sig_prepare_fork();
  syscall_clone_sigmask_pending = true;
  atomic_store_explicit(&syscall_fork_child_tls, child_tls,
                        memory_order_release);
}

/*
 * Fork/clone post-call initialization.
 */

void syscall_clone_child(void) {
  /*
   * The backend calls this for clone/clone3, including glibc fork; raw fork
   * calls it explicitly. Initialize the child's TLS state even when creation
   * happened inside a user hook; only user-hook participation is inherited.
   */

  /*
   * Inherited registrations and ownership lists must be coherent before a
   * signal can enter the child. Preserve the logical mask staged by clone.
   */
  kernel_sigset_t _inherited;
  log_verify(!patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &_inherited)));
  bool _cb = false;
  atomic_store_explicit(&syscall_user_cb_active, true, memory_order_relaxed);

  _overlaysys_syscall_self_tid = (pid_t)util_syscall_no_intercept(SYS_gettid);
  _overlaysys_syscall_self_pid = (pid_t)util_syscall_no_intercept(SYS_getpid);

  const bool _forked =
      atomic_load_explicit(&syscall_fork_child_tls, memory_order_acquire) ==
      (uintptr_t)__builtin_thread_pointer();
  if (_forked) {
    atomic_store_explicit(&syscall_hook_state, syscall_fork_state.hook_state,
                          memory_order_relaxed);
    _inherited = syscall_fork_state.mask;
    syscall_fd_thread_owner = syscall_fork_state.fd_owner;
    _cb = syscall_fork_state.cb;
    atomic_store_explicit(&syscall_app_errno_state,
                          syscall_fork_state.errno_state, memory_order_relaxed);
    atomic_store_explicit(&syscall_hook_errno_phase,
                          syscall_fork_state.errno_phase, memory_order_relaxed);
    if (!syscall_fork_state.continuation)
      errno = syscall_fork_state.errno_state.val;
    atomic_store_explicit(&syscall_fork_child_tls, 0, memory_order_relaxed);
    /*
     * A fork child has no surviving sibling threads or inherited lock owner.
     */
    sig_reset_fork(syscall_fork_state.continuation);
  } else {
    /*
     * A shared-VM thread may start with copied TLS. It must not release the
     * donor's signal/FD resources or reset process-wide state.
     */
    atomic_store_explicit(&syscall_hook_state, 0, memory_order_relaxed);
    sig_reset_thread();
    syscall_fd_thread_owner = syscall_fd_clone_owner = NULL;
    syscall_clone_sigmask = (kernel_sigset_t){0};
    atomic_store_explicit(&syscall_app_errno_state,
                          ((struct app_errno_state){.val = errno}),
                          memory_order_relaxed);
    atomic_store_explicit(&syscall_hook_errno_phase, ERRNO_APPLICATION,
                          memory_order_relaxed);
    atomic_store_explicit(&syscall_internal_emulation, false,
                          memory_order_relaxed);
  }
  syscall_clone_sigmask_pending = false;
  kernel_sigset_t _blocked;
  sig_lock_rt_sigaction(&_blocked);
  if (_forked)
    syscall_reset_fd_fork_locked(syscall_fork_state.continuation);
  else {
    syscall_fd_thread_owner =
        syscall_find_fd_owner_locked(_overlaysys_syscall_self_tid);
    log_verify(syscall_fd_thread_owner && syscall_fd_thread_owner->table);
    _inherited = syscall_fd_thread_owner->clone_mask;
    atomic_store_explicit(&syscall_hook_state,
                          syscall_fd_thread_owner->clone_wrapper_requested,
                          memory_order_relaxed);
  }
  sig_set_logical_sigmask(_inherited);
  if (_forked)
    sig_refresh_wrapped_sigactions(0);
  _inherited = sig_filter_logical_sigmask();
  sig_unlock_rt_sigaction(&_inherited);

  /*
   * Initialize this child's configured altstack after restoring ownership.
   */
  if (unlikely(sig_enable_defsigaltstack))
    log_verify_err(sig_init_defsigaltstack());

  hook_dispatch_clone_child_epilogues();

  atomic_store_explicit(&syscall_user_cb_active, _cb, memory_order_relaxed);
}

void syscall_clone_parent(long child_tid) {
  /*
   * Native failures arrive here too. Release the retained transaction before
   * invoking the parent callback.
   */

  if (syscall_clone_sigmask_pending) {
    syscall_clone_sigmask_pending = false;
    atomic_store_explicit(&syscall_fork_child_tls, 0, memory_order_release);
    syscall_finish_fd_clone_locked(child_tid);
    sig_unlock_with_replay(syscall_clone_sigmask, false);
  }

  hook_dispatch_clone_parent_epilogues(child_tid);
}

static __always_inline long syscall_raw_fork() {
  return util_syscall_no_intercept(SYS_fork);
}

/*
 * Unlike a new-stack clone or vfork, raw fork returns on the same copied C
 * stack in both processes. Keep its actual syscall number for kernel policies
 * and run the missing backend post-call callbacks exactly once ourselves.
 */
static long syscall_emulate_fork() {
  sig_lock_rt_sigaction(&syscall_clone_sigmask);
  sig_sync_logical_sigmask(syscall_clone_sigmask);
  syscall_prepare_private_fork_locked((uintptr_t)__builtin_thread_pointer(),
                                      true);
  const long _res = syscall_raw_fork();
  if (!_res)
    syscall_clone_child();
  else
    syscall_clone_parent(_res);
  return _res;
}

/*
 * Decide before entering the large emulation frame. Fault-only policies do not
 * require virtual readiness until a signalfd or software pending record exists.
 */
static __always_inline bool syscall_native_syscall(long num, long a, long d,
                                                   long e, long f) {
  const unsigned long _faults = (1UL << (SIGSEGV - 1)) | (1UL << (SIGBUS - 1));
  switch (num) {
  case SYS_epoll_create:
  case SYS_epoll_create1:
    return !atomic_load_explicit(&syscall_nr_signalfds, memory_order_relaxed) &&
           !(atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed) &
             ~_faults);
  case SYS_epoll_ctl:
    return !syscall_is_tracked_fd(a, false);
  case SYS_ppoll:
  case SYS_pselect6:
  case SYS_epoll_wait:
  case SYS_epoll_pwait:
  case SYS_epoll_pwait2:
    break;
  default:
    return false;
  }
  const unsigned long _inhibit =
      atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed);
  const bool _epoll = num == SYS_epoll_wait || num == SYS_epoll_pwait ||
                      num == SYS_epoll_pwait2;
  const bool _no_mask = (num == SYS_ppoll && !d) ||
                        (num == SYS_pselect6 && !f) || num == SYS_epoll_wait ||
                        (_epoll && !e);
  return (_no_mask ||
          (!_inhibit &&
           !atomic_load_explicit(&sig_wait_sighand, memory_order_acquire))) &&
         !(_inhibit & ~_faults) && !sig_has_pending() &&
         !hook_has_sig_hooks() &&
         (!_epoll || !syscall_is_tracked_fd(a, false)) &&
         !atomic_load_explicit(&syscall_nr_signalfds, memory_order_relaxed) &&
         !atomic_load_explicit(&syscall_nr_pending_epoll_events,
                               memory_order_relaxed);
}

/*
 * Fault-only, non-pedantic waits let the kernel own timeout and output copying.
 * Snapshot caller masks once with fault-safe copies; never validate a pointer
 * and then make the kernel fetch that mutable input again. A live assembly
 * frame still distinguishes the temporary delivery mask from the return mask.
 * Async fault replay/retry precision and racing native mask/policy edits are
 * outside this mode's temporary-wait guarantees.
 */
static bool syscall_native_masked_wait(long num, long a, long b, long c, long d,
                                       long e, long f, long *res) {
  if (sig_pedantic || (num != SYS_ppoll && num != SYS_pselect6))
    return false;
  const unsigned long _faults = (1UL << (SIGSEGV - 1)) | (1UL << (SIGBUS - 1));
  const unsigned long _inhibit =
      atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed);
  if ((_inhibit & ~_faults) || sig_has_pending() || hook_has_sig_hooks() ||
      atomic_load_explicit(&syscall_nr_signalfds, memory_order_relaxed) ||
      atomic_load_explicit(&syscall_nr_pending_epoll_events,
                           memory_order_relaxed))
    return false;

  const kernel_sigset_t *_mask = addr_cast(d);
  size_t _size = e;
  if (num == SYS_pselect6) {
    struct {
      const kernel_sigset_t *set;
      size_t size;
    } _arg;
    if (!f || syscall_copy_user_mem(&_arg, addr_cast(f), sizeof(_arg)))
      return false;
    _mask = _arg.set;
    _size = _arg.size;
    if (!_mask) {
      *res = util_syscall_no_intercept(num, a, b, c, d, e, 0L);
      return true;
    }
  }
  if (!_mask || _size != sizeof(kernel_sigset_t) ||
      atomic_load_explicit(&sig_wait_sighand, memory_order_acquire))
    return false;
  struct wait_call _call = {
      .num = num, .args = {a, b, c, d, e, f}, .native = true};
  if (syscall_copy_user_mem(&_call.temporary, _mask, sizeof(_call.temporary)))
    return false;
  _call.temporary.__val[0] &=
      ~((1UL << (SIGKILL - 1)) | (1UL << (SIGSTOP - 1)));
  _call.orig = sig_logical_sigmask;
  _call.entry_mask = _call.temporary;
  _call.entry_mask.__val[0] &= ~_inhibit;
  if (num == SYS_ppoll) {
    _call.args[3] = (long)&_call.entry_mask;
    _call.args[4] = sizeof(_call.entry_mask);
    *res = sig_raw_ppoll(&_call);
  } else {
    const struct {
      const kernel_sigset_t *set;
      size_t size;
    } _arg = {&_call.entry_mask, sizeof(_call.entry_mask)};
    _call.args[5] = (long)&_arg;
    *res = sig_raw_pselect6(&_call);
  }
  return true;
}

static int syscall_emulate_syscall(long num, long a, long b, long c, long d,
                                   long e, long f, long *restrict res) {
  switch (num) {
  case SYS_clone:
  case SYS_clone3: {
    unsigned long _flags = a;
    int _err = 0;
    if (num == SYS_clone3) {
      if ((unsigned long)b < CLONE_ARGS_SIZE_VER0)
        _err = -EINVAL;
      else if ((unsigned long)b > 4096)
        _err = -E2BIG;
      else
        _err = syscall_copy_user_mem(&_flags, addr_cast(a), sizeof(_flags));
    }
    const bool _shared = _flags & CLONE_VM;
    const unsigned long _thread_flags =
        CLONE_THREAD | CLONE_SIGHAND | CLONE_SETTLS;
    if (!_err && ((_flags & CLONE_VFORK) ||
                  (_shared && (_flags & _thread_flags) != _thread_flags)))
      _err = -EOPNOTSUPP;
    bool _continuation = !b;
    if (!_err && num == SYS_clone3) {
      struct {
        unsigned long addr, size;
      } _stack;
      _err = syscall_copy_user_mem(
          &_stack, addr_cast((uintptr_t)a + offsetof(struct clone_args, stack)),
          sizeof(_stack));
      if (!_err) {
        _continuation = !_stack.addr;
        if (_shared && (!_stack.addr || !_stack.size))
          _err = -EOPNOTSUPP;
      }
    } else if (!_err && _shared && !b)
      _err = -EOPNOTSUPP;
    unsigned long _tls = (unsigned long)__builtin_thread_pointer();
    if (!_err && (_flags & CLONE_SETTLS)) {
      if (num == SYS_clone3)
        _err = syscall_copy_user_mem(
            &_tls, addr_cast((uintptr_t)a + offsetof(struct clone_args, tls)),
            sizeof(_tls));
      else
        _tls = e;
    }
    if (!_err && _shared &&
        (!_tls || _tls == (unsigned long)__builtin_thread_pointer()))
      _err = -EOPNOTSUPP;
    if (_err) {
      *res = _err;
      hook_dispatch_clone_parent_epilogues(_err);
      return 0;
    }
    sig_lock_rt_sigaction(&syscall_clone_sigmask);
    sig_sync_logical_sigmask(syscall_clone_sigmask);
    _err = syscall_prepare_fd_clone_locked(_flags);
    if (_err) {
      *res = _err;
      sig_unlock_rt_sigaction(&syscall_clone_sigmask);
      hook_dispatch_clone_parent_epilogues(_err);
      return 0;
    }
    if (!_shared)
      syscall_prepare_private_fork_locked(_tls, _continuation);
    else {
      /*
       * The parent publishes the reserved owner/mask before a shared child can
       * acquire this lock. Keep fset across the kernel and both callbacks.
       */
      syscall_clone_sigmask_pending = true;
    }
    return 1;
  }

  case SYS_fork:
    *res = syscall_emulate_fork();
    break;

  case SYS_vfork:
    *res = -EOPNOTSUPP;
    break;

  case SYS_exit:
    *res = syscall_emulate_exit(a);
    break;

  case SYS_rt_sigaction:
    *res = sig_emulate_rt_sigaction(a, addr_cast(b), addr_cast(c), d);
    break;

  case SYS_rt_sigprocmask:
    *res = sig_emulate_rt_sigprocmask(a, addr_cast(b), addr_cast(c), d);
    break;

  case SYS_read:
  case SYS_readv:
    return syscall_emulate_signalfd_read(num, a, addr_cast(b), c, res);

  case SYS_signalfd:
    *res = syscall_emulate_signalfd4(a, addr_cast(b), c, 0);
    break;
  case SYS_signalfd4:
    *res = syscall_emulate_signalfd4(a, addr_cast(b), c, d);
    break;
  case SYS_epoll_ctl:
    return syscall_emulate_epoll_ctl(a, b, c, addr_cast(d), res);
  case SYS_epoll_create:
  case SYS_epoll_create1:
  case SYS_close:
  case SYS_dup:
  case SYS_dup2:
  case SYS_dup3:
  case SYS_fcntl:
    return syscall_emulate_fd_op(num, a, b, c, res);
  case SYS_unshare:
    return syscall_emulate_fd_unshare(num, a, b, c, res);
  case SYS_close_range:
    if (c & CLOSE_RANGE_UNSHARE)
      return syscall_emulate_fd_unshare(num, a, b, c, res);
    return syscall_emulate_fd_op(num, a, b, c, res);

  case SYS_rt_sigtimedwait:
    *res = sig_emulate_rt_sigtimedwait(addr_cast(a), addr_cast(b), addr_cast(c),
                                       d);
    break;

  case SYS_rt_sigpending:
    *res = sig_emulate_rt_sigpending(addr_cast(a), b);
    break;

  case SYS_poll:
  case SYS_select:
    if (!atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed) &&
        !atomic_load_explicit(&syscall_nr_signalfds, memory_order_relaxed) &&
        !atomic_load_explicit(&syscall_nr_pending_epoll_events,
                              memory_order_relaxed))
      return 1;
    /*
     * Signal-aware waits still need their delivery/return mask distinction.
     */
    fallthrough;
  case SYS_rt_sigsuspend:
  case SYS_epoll_wait:
  case SYS_ppoll:
  case SYS_pselect6:
  case SYS_epoll_pwait:
  case SYS_epoll_pwait2:
    if (syscall_native_masked_wait(num, a, b, c, d, e, f, res))
      break;
    *res = syscall_emulate_masked_wait(num, a, b, c, d, e, f);
    break;

  case SYS_sigaltstack:
    if (!sig_defsigstk && !sig_enable_sigaltstackautodisarm &&
        !sig_enable_sigaltstackeperm)
      return 1;
    *res = sig_emulate_sigaltstack(addr_cast(a), addr_cast(b));
    break;

  default:
    /*
     * Other calls remain native; exit_group also lets the kernel reclaim the
     * entire address space instead of running per-thread teardown.
     */
    return 1;
  }
  return 0;
}

int syscall_intercept(long num, long a, long b, long c, long d, long e, long f,
                      long *restrict ret) {
  /*
   * Return 1 for backend execution, or 0 with the raw result in *ret.
   */

  /*
   * Internal critical sections bypass dispatch. Inherited ineligibility or an
   * active callback suppresses user syscall hooks and epilogues, retaining
   * required emulation. Managed waits release the internal guard before signal
   * delivery or blocking.
   */
  if (!_overlaysys_syscall_self_tid ||
      atomic_load_explicit(&syscall_internal_emulation, memory_order_relaxed))
    return 1;
  if (!atomic_load_explicit(&patch_interception_ready, memory_order_relaxed) ||
      atomic_load_explicit(&syscall_hook_state, memory_order_relaxed) != 1 ||
      atomic_load_explicit(&syscall_user_cb_active, memory_order_relaxed)) {
    if (!sig_pedantic && syscall_native_syscall(num, a, d, e, f))
      return 1;
    return syscall_emulate_syscall(num, a, b, c, d, e, f, ret);
  }

  if (!hook_dispatch_syscall_hooks(num, a, b, c, d, e, f, ret))
    return 0;
  const int native =
      (!sig_pedantic && syscall_native_syscall(num, a, d, e, f)) ||
      syscall_emulate_syscall(num, a, b, c, d, e, f, ret);
  if (!hook_has_syscall_epilogues())
    return native;

  /* Clone completion has its own epilogues; sigreturn resumes another frame.
   * Keep these calls on their existing backend or emulation return paths. */
  switch (num) {
  case SYS_clone:
  case SYS_clone3:
  case SYS_fork:
  case SYS_vfork:
  case SYS_rt_sigreturn:
    return native;
  }

  /* Complete native calls here only when an epilogue needs their result.
   * Successful exit/exec calls do not return and therefore have no epilogue. */
  if (native)
    *ret = util_syscall_no_intercept(num, a, b, c, d, e, f);
  hook_dispatch_syscall_epilogues(num, a, b, c, d, e, f, ret);
  return 0;
}

/*
 * Initialization.
 */

int syscall_prepare_runtime(void) {
  static void *pthread_namespace;
  static bool vdso_ready;
  /* Before any patch, only one thread can acquire its initial tracked state. */
  DIR *const directory = opendir("/proc/self/task");
  if (!directory)
    return -1;
  size_t threads = 0;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(directory))) {
    if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9')
      ++threads;
  }
  int err = errno;
  if (closedir(directory) && !err)
    err = errno;
  if (!err && threads != 1)
    err = EBUSY;
  if (err) {
    errno = err;
    return -1;
  }
  if (!pthread_namespace) {
    pthread_namespace = dlmopen(LM_ID_NEWLM, "libpthread.so.0", RTLD_LAZY);
    if (!pthread_namespace) {
      /* The loader reports dlerror strings, not a stable errno contract. */
      errno = ELIBACC;
      return -1;
    }
  }
  const long thread = util_syscall_no_intercept(SYS_gettid);
  const long proc = util_syscall_no_intercept(SYS_getpid);
  err = patcher_syscall_err_code(thread);
  if (!err)
    err = patcher_syscall_err_code(proc);
  if (!err &&
      ((_overlaysys_syscall_self_tid &&
        _overlaysys_syscall_self_tid != thread) ||
       (_overlaysys_syscall_self_pid && _overlaysys_syscall_self_pid != proc)))
    err = EBUSY;
  if (err) {
    errno = err;
    return -1;
  }
  _overlaysys_syscall_self_tid = (pid_t)thread;
  _overlaysys_syscall_self_pid = (pid_t)proc;

  if (!vdso_ready) {
    void *const vdso =
        dlopen("linux-vdso.so.1", RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
    if (vdso) {
      /* Missing vDSO symbols use the existing raw clock_gettime fallback. */
      syscall_vdso_clock_gettime = (typeof(syscall_vdso_clock_gettime))dlvsym(
          vdso, "__vdso_clock_gettime", "LINUX_2.6");
      if (dlclose(vdso)) {
        errno = EIO;
        return -1;
      }
    }
    vdso_ready = true;
  }

  /* Keep existing/default lock-spin tuning. The optional usersched calibrator
   * can terminate on host restrictions; it cannot run in a returning API. */
  if (!syscall_fd_thread_owner) {
    struct sig_lock_scope scope;
    err = sig_lock_sig_scope(&scope);
    if (err) {
      errno = err;
      return -1;
    }
    const int res = syscall_init_fd_table_locked();
    if (sig_unlock_sig_scope(&scope, res < 0 ? -res : 0))
      return -1;
  }
  if (sig_init_interception())
    return -1;
  return sig_init_env();
}

int overlaysys_syscall_hook_disable(void) noexcept {
  uint64_t state =
      atomic_load_explicit(&syscall_hook_state, memory_order_relaxed);
  do {
    if ((state >> 1) == UINT_MAX) {
      errno = EOVERFLOW;
      return -1;
    }
  } while (!atomic_compare_exchange_weak_explicit(
      &syscall_hook_state, &state, state + 2, memory_order_relaxed,
      memory_order_relaxed));
  return 0;
}

int overlaysys_syscall_hook_enable(void) noexcept {
  uint64_t state =
      atomic_load_explicit(&syscall_hook_state, memory_order_relaxed);
  do {
    if (!(state >> 1)) {
      errno = EINVAL;
      return -1;
    }
  } while (!atomic_compare_exchange_weak_explicit(
      &syscall_hook_state, &state, state - 2, memory_order_relaxed,
      memory_order_relaxed));
  return 0;
}

long _overlaysys_syscall(long num, ...) noexcept {
  va_list _ap;
  va_start(_ap, num);
  register long _raw_ret asm("rax") = num;
  const register long _a asm("rdi") = va_arg(_ap, long);
  const register long _b asm("rsi") = va_arg(_ap, long);
  const register long _c asm("rdx") = va_arg(_ap, long);
  const register long _d asm("r10") = va_arg(_ap, long); // Kernel argument 4.
  const register long _e asm("r8") = va_arg(_ap, long);
  const register long _f asm("r9") = va_arg(_ap, long);
  va_end(_ap);

  /*
   * The memory clobber prevents reordering accesses through syscall pointers.
   * x86-64 syscall uses r10 for argument four and clobbers rcx/r11.
   */
  asm volatile("syscall"
               : "=a"(_raw_ret)
               : "0"(_raw_ret), "D"(_a), "S"(_b), "d"(_c), "r"(_d), "r"(_e),
                 "r"(_f)
               : "rcx", "r11", "memory");
  /*
   * Convert the raw kernel error convention only at this libc-style boundary.
   */
  const int _errno = patcher_syscall_err_code(_raw_ret);
  if (unlikely(_errno)) {
    errno = _errno;
    return -1;
  }
  return _raw_ret;
}
