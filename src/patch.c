#include "internal.h"

_Atomic bool patch_interception_ready;
static _Atomic bool patch_busy;

static int patch_libraries(bool all, size_t len, const char *const *paths,
                           bool skip_missing) {
  const int saved_errno = errno;
  if (len && !paths) {
    errno = EINVAL;
    return -1;
  }
  if (len > SIZE_MAX / sizeof(*paths)) {
    errno = EOVERFLOW;
    return -1;
  }
  for (size_t i = 0; i < len; ++i) {
    if (!paths[i] || !paths[i][0]) {
      errno = EINVAL;
      return -1;
    }
  }
  if (atomic_load_explicit(&syscall_user_cb_active, memory_order_relaxed) ||
      atomic_load_explicit(&syscall_internal_emulation, memory_order_relaxed)) {
    errno = EDEADLK;
    return -1;
  }
  if (atomic_exchange_explicit(&patch_busy, true, memory_order_acq_rel)) {
    errno = EBUSY;
    return -1;
  }
  int err = 0;
  if (!atomic_load_explicit(&patch_interception_ready, memory_order_acquire) &&
      syscall_prepare_runtime()) {
    err = errno ? errno : EIO;
    goto done;
  }
  if (_overlaysys_syscall_self_tid <= 0) {
    err = ENODEV;
    goto done;
  }

  kernel_sigset_t saved_mask;
  err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &saved_mask));
  if (err)
    goto done;
  atomic_store_explicit(&syscall_internal_emulation, true,
                        memory_order_relaxed);
  /* Prepared state must serve any patches that a failing backend already made.
   */
  atomic_store_explicit(&patch_interception_ready, true, memory_order_release);
  const int res = all ? patcher_patch_all(len, paths)
                      : patcher_patch(len, paths, skip_missing);
  if (res)
    err = errno ? errno : EIO;
  atomic_store_explicit(&syscall_internal_emulation, false,
                        memory_order_relaxed);
  atomic_store_explicit(&patch_busy, false, memory_order_release);
  const int restore_err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &saved_mask, NULL));
  if (!err)
    err = restore_err;
  errno = err ? err : saved_errno;
  return err ? -1 : 0;

done:
  atomic_store_explicit(&patch_busy, false, memory_order_release);
  errno = err;
  return -1;
}

/*
 * Public variables and functions.
 */

int overlaysys_patch(size_t len, const char *const *restrict paths,
                     bool skip_missing) noexcept {
  return patch_libraries(false, len, paths, skip_missing);
}

int overlaysys_patch_all(size_t len,
                         const char *const *restrict inhibit_patch) noexcept {
  return patch_libraries(true, len, inhibit_patch, true);
}

int overlaysys_patch_check(const char *restrict path,
                           bool *restrict check) noexcept {
  const int saved_errno = errno;
  if (!check || (path && !path[0])) {
    errno = EINVAL;
    return -1;
  }
  if (atomic_exchange_explicit(&patch_busy, true, memory_order_acq_rel)) {
    errno = EBUSY;
    return -1;
  }

  kernel_sigset_t saved_mask;
  int err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &saved_mask));
  if (err) {
    atomic_store_explicit(&patch_busy, false, memory_order_release);
    errno = err;
    return -1;
  }
  const bool internal = atomic_exchange_explicit(&syscall_internal_emulation,
                                                 true, memory_order_relaxed);
  bool patched;
  if (patcher_patch_check(path, &patched))
    err = errno ? errno : EIO;
  atomic_store_explicit(&syscall_internal_emulation, internal,
                        memory_order_relaxed);
  atomic_store_explicit(&patch_busy, false, memory_order_release);
  const int restore_err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &saved_mask, NULL));
  if (!err)
    err = restore_err;
  if (!err)
    *check = patched;
  errno = err ? err : saved_errno;
  return err ? -1 : 0;
}
