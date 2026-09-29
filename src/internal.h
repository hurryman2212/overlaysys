#pragma once

#include <stdatomic.h>

#include <sys/syscall.h>

#include "overlaysys.h"

#include "patcher/patcher.h"

/*
 * Shared implementation contracts; never installed as public API.
 */
#define _INTERNAL __attribute__((visibility("hidden")))

#define kernel_sa_handler sigaction_handler._kernel_sa_handler
#define kernel_sa_sigaction sigaction_handler._kernel_sa_sigaction

extern _INTERNAL int sig_enable_sigaltstackautodisarm,
    sig_enable_sigaltstackeperm;

extern _INTERNAL size_t sig_enable_defsigaltstack;

extern _INTERNAL thread_local
    __attribute((tls_model("initial-exec"))) void *sig_defsigstk;

/*
 * Linux x86-64 signal syscall ABI; libc sigset_t is larger.
 */
typedef struct {
  unsigned long __val[(NSIG - 1) / (8 * sizeof(unsigned long))];
} kernel_sigset_t;

static_assert(sizeof(kernel_sigset_t) == sizeof(unsigned long));

static_assert(ATOMIC_LONG_LOCK_FREE == 2);

extern _INTERNAL _Atomic unsigned long sig_inhibit_sigblock;

extern _INTERNAL bool sig_pedantic;

extern _INTERNAL _Atomic unsigned long sig_wait_sighand;

extern _INTERNAL thread_local __attribute((
    tls_model("initial-exec"))) kernel_sigset_t sig_logical_sigmask;

extern _INTERNAL thread_local
    __attribute((tls_model("initial-exec"))) bool syscall_clone_sigmask_pending;

/*
 * syscall_user_cb_active skips user syscall hooks but keeps emulation;
 * syscall_internal_emulation bypasses both inside signal-blocked critical
 * sections.
 */
extern _INTERNAL thread_local __attribute((
    tls_model("initial-exec"))) _Atomic bool syscall_user_cb_active,
    syscall_internal_emulation;

/*
 * Wrapped handlers publish errno and its serial atomically so nested delivery
 * cannot pair a new serial with an old value. Native exemptions bypass this.
 */
struct app_errno_state {
  uint32_t generation;
  int val;
};
static_assert(sizeof(struct app_errno_state) == sizeof(uint64_t));
static_assert(ATOMIC_LLONG_LOCK_FREE == 2);
extern _INTERNAL thread_local __attribute((tls_model(
    "initial-exec"))) _Atomic(struct app_errno_state) syscall_app_errno_state;
/*
 * RESTORING prevents an interrupting wrapper from publishing transient errno.
 */
enum cb_errno_phase { ERRNO_APPLICATION, ERRNO_HOOK, ERRNO_RESTORING };
struct cb_errno_scope {
  enum cb_errno_phase phase;
  int saved_errno;
};
extern _INTERNAL thread_local __attribute((tls_model(
    "initial-exec"))) _Atomic enum cb_errno_phase syscall_hook_errno_phase;

static __always_inline void internal_publish_app_errno(void) {
  struct app_errno_state _prev =
      atomic_load_explicit(&syscall_app_errno_state, memory_order_relaxed);
  const int _val = errno;
  if (_prev.val == _val)
    return;
  const struct app_errno_state _next = {.generation = _prev.generation + 1,
                                        .val = _val};
  /*
   * If a nested handler published after our snapshot, its newer value wins.
   */
  atomic_compare_exchange_strong_explicit(&syscall_app_errno_state, &_prev,
                                          _next, memory_order_relaxed,
                                          memory_order_relaxed);
}

static __always_inline void internal_restore_app_errno(void) {
  /*
   * A nested application handler may publish between the load and errno write.
   */
  for (;;) {
    const struct app_errno_state _before =
        atomic_load_explicit(&syscall_app_errno_state, memory_order_relaxed);
    errno = _before.val;
    const struct app_errno_state _after =
        atomic_load_explicit(&syscall_app_errno_state, memory_order_relaxed);
    /* The state has no padding: compare the complete atomic snapshot. */
    if (!__builtin_memcmp(&_before, &_after, sizeof(_before)))
      return;
  }
}

static __always_inline struct cb_errno_scope internal_hook_errno_enter(void) {
  const struct cb_errno_scope _scope = {
      .phase =
          atomic_load_explicit(&syscall_hook_errno_phase, memory_order_relaxed),
      .saved_errno = errno};
  if (_scope.phase == ERRNO_APPLICATION)
    internal_publish_app_errno();
  atomic_store_explicit(&syscall_hook_errno_phase, ERRNO_HOOK,
                        memory_order_relaxed);
  internal_restore_app_errno();
  return _scope;
}

static __always_inline void
internal_hook_errno_leave(struct cb_errno_scope scope) {
  if (scope.phase == ERRNO_HOOK) {
    /*
     * A resumed callback still needs its own backend errno. A nested handler's
     * application-visible change remains published for the outer boundary.
     */
    atomic_store_explicit(&syscall_hook_errno_phase, ERRNO_HOOK,
                          memory_order_relaxed);
    errno = scope.saved_errno;
  } else {
    /*
     * A signal interrupting this transition must not publish a transient
     * callback errno as application state. Publish the application phase only
     * after the final restoration write.
     */
    atomic_store_explicit(&syscall_hook_errno_phase, ERRNO_RESTORING,
                          memory_order_relaxed);
    internal_restore_app_errno();
    atomic_store_explicit(&syscall_hook_errno_phase, scope.phase,
                          memory_order_relaxed);
  }
}

/*
 * Commit a completed replacement error, rather than incidental callback errno.
 */
static __always_inline void
internal_hook_errno_fail(struct cb_errno_scope scope, int err) {
  if (scope.phase == ERRNO_HOOK) {
    scope.saved_errno = err;
    internal_hook_errno_leave(scope);
    return;
  }
  struct app_errno_state _old =
      atomic_load_explicit(&syscall_app_errno_state, memory_order_relaxed);
  struct app_errno_state _next;
  do {
    _next =
        (struct app_errno_state){.generation = _old.generation + 1, .val = err};
  } while (!atomic_compare_exchange_weak_explicit(
      &syscall_app_errno_state, &_old, _next, memory_order_relaxed,
      memory_order_relaxed));
  internal_hook_errno_leave(scope);
}

/*
 * Original handlers run in application mode even when interrupting a hook.
 * Nonlocal exits leave that mode active; no errno scope pointer is stored in
 * TLS.
 */
static __always_inline struct cb_errno_scope
internal_handler_errno_enter(void) {
  const struct cb_errno_scope _scope = {
      .phase =
          atomic_load_explicit(&syscall_hook_errno_phase, memory_order_relaxed),
      .saved_errno = errno};
  atomic_store_explicit(&syscall_hook_errno_phase, ERRNO_RESTORING,
                        memory_order_relaxed);
  if (_scope.phase != ERRNO_APPLICATION)
    internal_restore_app_errno();
  atomic_store_explicit(&syscall_hook_errno_phase, ERRNO_APPLICATION,
                        memory_order_relaxed);
  return _scope;
}

static __always_inline void
internal_handler_errno_leave(struct cb_errno_scope scope) {
  internal_publish_app_errno();
  internal_hook_errno_leave(scope);
}

/*
 * Raw x86-64 rt_sigaction layout, including the userspace signal restorer.
 */
struct kernel_sigaction {
  union {
    void (*_kernel_sa_handler)(int);

    void (*_kernel_sa_sigaction)(int, siginfo_t *, void *);

  } sigaction_handler;
  unsigned long sa_flags;
  void (*sa_restorer)();
  kernel_sigset_t sa_mask;
};

static __always_inline pid_t internal_raw_getpid() {
  return util_syscall_no_intercept(SYS_getpid);
}

/*
 * Packet associated with a live assembly-owned wait frame; never publish its
 * address in TLS.
 *
 * temporary/original are logical masks; entry_mask is the physical read mask.
 * The original mask can be updated by signal-context edits before return.
 */
struct wait_call {
  long num, args[6];
  kernel_sigset_t temporary, orig;
  bool intercepted, swallowed, read_interrupted, entry_restored;
  /*
   * Wrapped nonrestart-handler count before a potentially interrupted read.
   */
  unsigned long read_generation;
  kernel_sigset_t entry_mask;
  /* Native waits return once; consumed signals must restore the original mask.
   */
  bool native;
  /* Establish the live wait frame before restoring the entry signal mask. */
  bool entry_guard;
  bool saved_dispatch;
};

/*
 * Offsets and syscall numbers embedded in sig.c's x86-64 wait bridge.
 */
static_assert(sizeof(long) == 8 && offsetof(struct wait_call, args) == 8);

static_assert(offsetof(struct wait_call, entry_restored) == 75 &&
              offsetof(struct wait_call, entry_mask) == 88 &&
              offsetof(struct wait_call, entry_guard) == 97);

static_assert(SYS_read == 0 && SYS_rt_sigprocmask == 14 && SIG_SETMASK == 2 &&
              sizeof(kernel_sigset_t) == 8);

static_assert(SYS_getpid == 39);

static __always_inline void *internal_raw_mmap(void *addr, size_t len, int prot,
                                               int flags, int fd, off64_t off) {
  return (void *)util_syscall_no_intercept(SYS_mmap, addr, len, prot, flags, fd,
                                           off);
}

static __always_inline int internal_raw_munmap(void *addr, size_t len) {
  return util_syscall_no_intercept(SYS_munmap, addr, len);
}

/*
 * Signal/FD state protected by the action lock.
 */
extern _INTERNAL uint32_t sig_rt_sigaction_lock;
extern _INTERNAL unsigned long sig_deferred_seq;

/*
 * forwarded_sigs counts user handlers and Term/Core/Stop dispatches;
 * nonrestart_sigs counts handlers without requested SA_RESTART. Manual
 * continuation calls count too; native initialization exemptions remain
 * unobserved.
 */
extern _INTERNAL thread_local
    __attribute((tls_model("initial-exec"))) unsigned long sig_forwarded_sigs,
    sig_nonrestart_sigs;

static_assert(sizeof(uintptr_t) == sizeof(unsigned long));
static_assert(ATOMIC_LONG_LOCK_FREE == 2 && ATOMIC_POINTER_LOCK_FREE == 2);

/* Fallible setup/policy critical sections. Lock returns a positive errno;
 * unlock attempts all cleanup and returns 0 or -1 with the first errno. */
struct sig_lock_scope {
  kernel_sigset_t mask;
  bool internal;
  int saved_errno;
};

/* Registry traversal requires caller-serialized registration changes.
 * Declarations in each source group follow its definition order. */
extern _INTERNAL int hook_backing_fd;
_INTERNAL int hook_resize_backing(int fd, size_t bytes);
_INTERNAL void hook_prepare_fork(void);
_INTERNAL int hook_dispatch_syscall_hooks(long num, long a, long b, long c,
                                          long d, long e, long f, long *res);
_INTERNAL bool hook_has_syscall_epilogues(void);
_INTERNAL void hook_dispatch_syscall_epilogues(long num, long a, long b, long c,
                                               long d, long e, long f,
                                               long *ret);
_INTERNAL bool hook_has_sig_hooks(void);
_INTERNAL void hook_dispatch_sig_hooks(int sig, siginfo_t *info, void *ctx,
                                       int *forward, const extsiginfo_t *extra);
_INTERNAL void hook_dispatch_clone_child_epilogues(void);
_INTERNAL void hook_dispatch_clone_parent_epilogues(pid_t child_tid);

/* syscall.c: zero means a complete copy; negative errno may follow a partial
 * write. Callers split transfers above PIPE_BUF for the private-pipe fallback.
 */
_INTERNAL int syscall_copy_user_mem(void *dest, const void *src, size_t size);
_INTERNAL int syscall_resize_hook_backing(size_t bytes);
_INTERNAL void syscall_refresh_fd_edges_locked(void);
_INTERNAL struct timespec syscall_wait_deadline(struct timespec timeout);
_INTERNAL struct timespec syscall_wait_remaining(struct timespec deadline);

/* sig.c */
_INTERNAL int sig_raw_rt_sigprocmask(int signum,
                                     const kernel_sigset_t *restrict set,
                                     kernel_sigset_t *restrict oldset);
extern _INTERNAL const kernel_sigset_t sig_fset;
_INTERNAL int sig_init_interception(void);
_INTERNAL void sig_unmap_defsigstk(void);
_INTERNAL bool sig_on_defsigstk(const void *addr);
_INTERNAL int sig_emulate_sigaltstack(const stack_t *restrict ss,
                                      stack_t *restrict old_ss);
_INTERNAL void sig_prepare_fork(void);
_INTERNAL bool sig_has_pending(void);
_INTERNAL bool sig_has_captured(void);
_INTERNAL unsigned long sig_pending_seq(unsigned long mask);
_INTERNAL void sig_reset_fork(bool continuation);
_INTERNAL void sig_reset_thread(void);

/*
 * sig_lock_rt_sigaction blocks physical signals before taking the nonrecursive
 * signal/FD lock. No user callbacks may run while it is held.
 *
 * Ordinary unlock may skip an already-full mask restore. Default forwarding's
 * temporary unblock requires the private forced-restore helper instead.
 */
_INTERNAL void sig_lock_rt_sigaction(kernel_sigset_t *oldmask);
_INTERNAL void sig_unlock_rt_sigaction(const kernel_sigset_t *oldmask);

/* Mask/action helpers require the action lock and blocked signals. */
_INTERNAL void sig_refresh_wrapped_sigactions(unsigned long changed_mask);
_INTERNAL void sig_set_logical_sigmask(kernel_sigset_t mask);
_INTERNAL void sig_exit_sig_state(void);
_INTERNAL void sig_sync_logical_sigmask(kernel_sigset_t actual);
_INTERNAL kernel_sigset_t sig_filter_logical_sigmask(void);
_INTERNAL void sig_unlock_with_replay(kernel_sigset_t mask, bool sigreturn);

/* Syscall emulators acquire/release their own locks. */
_INTERNAL int sig_emulate_rt_sigaction(
    int signum, const struct kernel_sigaction *restrict kact,
    struct kernel_sigaction *restrict oldkact, size_t sigsetsize);
_INTERNAL int sig_emulate_rt_sigprocmask(int how,
                                         const kernel_sigset_t *restrict set,
                                         kernel_sigset_t *restrict oldset,
                                         size_t sigsetsize);
_INTERNAL int sig_emulate_rt_sigpending(kernel_sigset_t *set,
                                        size_t sigsetsize);
_INTERNAL long sig_raw_ppoll(struct wait_call *call);
_INTERNAL long sig_raw_pselect6(struct wait_call *call);
_INTERNAL long sig_raw_read_wait(struct wait_call *call);

/* Returns with the action lock reacquired; signals may run during the wait. */
_INTERNAL long sig_run_masked_wait(struct wait_call *call);
_INTERNAL int sig_proc_native_sig(int sig, siginfo_t *info);
_INTERNAL int sig_take_pending_sig(unsigned long mask, siginfo_t *info);
_INTERNAL long sig_emulate_rt_sigtimedwait(const kernel_sigset_t *set,
                                           siginfo_t *info,
                                           const struct timespec *timeout,
                                           size_t size);
_INTERNAL int sig_init_defsigaltstack(void);
_INTERNAL int sig_lock_sig_scope(struct sig_lock_scope *scope);
_INTERNAL int sig_unlock_sig_scope(const struct sig_lock_scope *scope, int err);
_INTERNAL int sig_init_env(void);

/* Explicit patch activation and shared runtime readiness. */
extern _INTERNAL _Atomic bool patch_interception_ready;
_INTERNAL int syscall_prepare_runtime(void);
