/**
 * @file overlaysys.h
 * @brief Linux x86-64 syscall patching and syscall, signal, and lifecycle
 * hooks.
 *
 * @see overlaysys_registration for callback ordering, lifetime, storage, and
 * caller synchronization requirements.
 *
 * @section overlaysys_context Calling conventions and context
 * Syscall arguments use kernel layouts; replacement and epilogue results use
 * libc conventions (-1 with errno on failure). Incidental callback errno
 * changes are discarded; replacement/final epilogue errors and original-handler
 * changes remain visible. Callbacks and waits run without internal locks. Hooks
 * may do real-FD I/O, wait, and query logical signal settings, subject to their
 * calling context. C++ callbacks need not be noexcept, but exceptions must not
 * escape; exception handling in signal context is unsupported.
 *
 * Both modes below preserve arithmetic/direction flags and CPU/OS-enabled
 * x87/MMX, SSE, AVX, and AVX-512 state, including FP controls, across C
 * processing. C hooks enter with an empty x87 stack; rcx/r11 retain syscall-ABI
 * clobbers. Unrelated state such as PKRU is not restored over native syscall
 * effects. Timing, scheduling, resource use, patched code, and memory layout
 * remain observable; /proc, ptrace, and seccomp expose actual kernel state.
 *
 * @section overlaysys_waits Waits and restart behavior
 * Emulated signal and I/O multiplexing waits retry hook-only interruptions
 * without extending timeouts; wrapped application-handler delivery preserves
 * EINTR. Signalfd I/O follows wrapped-handler restart decisions. Other syscalls
 * remain native: consumed signals may cause EINTR, and policy-forced SA_RESTART
 * may restart otherwise interruptible calls. Native exempt handlers bypass
 * errno/delivery bookkeeping and must preserve errno when interrupting hooks;
 * mixed native/wrapped deliveries cannot guarantee exact restart behavior.
 *
 * @section overlaysys_pedantic Pedantic mode
 * OVERLAYSYS_PEDANTIC accepts only 0 or 1, is read during initialization, and
 * is fixed for the process lifetime. Use 1 for full pending/readiness and
 * interruption emulation. Unset or 0 enables eligible native paths with the
 * limits below. Both modes retain signal hooks/delivery, original-handler
 * continuation and notifications, fault fixup, logical actions/masks, direct
 * signal consumers, and clone ownership.
 *
 * With 0, supported CPUs may skip saving CPU-reported initial x87 state until
 * x87/MMX use is observed in that thread. Only raw historical x87 opcode (FOP)
 * bits in otherwise initial state may be lost; arithmetic, control/exception,
 * and other FP/SIMD state remain preserved. Mode 1 always uses ordinary saves.
 *
 * Native ppoll, pselect6, and epoll waits use kernel timeout,
 * pointer-validation, and interruption rules. Eligibility requires no software
 * pending records, active signalfds, retained epoll events, or inhibition
 * beyond SIGSEGV/SIGBUS:
 * - Without a temporary mask, fault-only inhibition is allowed: the physical
 *   mask is already filtered. pselect6 with a NULL inner mask pointer also uses
 *   this path after safely snapshotting its argument structure.
 * - With a temporary mask, ppoll/pselect6 safely snapshot it, remove inhibited
 *   fault bits, and retain a live frame separating delivery and return masks.
 *   Other temporary-mask waits require no inhibition. Wrapped application
 *   handlers require full emulation; default/ignored SIGSEGV/SIGBUS hooks count
 *   as fault observers. Stale action bits may conservatively retain emulation.
 * - Epolls created while signalfds or nonfault inhibition exist stay tracked,
 *   including aliases/event decoding after those conditions end. Otherwise,
 *   native registrations/user data retain kernel ET, ONESHOT, alias, and shared
 *   description semantics. Fault-only inhibition alone does not select
 * tracking; tracked epolls stay emulated.
 *
 * Native-path limits:
 * - Hook-consumed signals may expose EINTR without retry; forwarded application
 *   handlers still run and are recorded. Output faults follow kernel behavior
 *   without retaining an epoll event suffix separately.
 * - Native epolls do not synthesize later software-pending readiness from
 *   signalfd or nested tracked epolls. Create signalfds or configure nonfault
 *   inhibition before creating such epolls, or use mode 1.
 * - Coordinate disposition/inhibition and virtual-readiness changes with
 *   in-flight native waits: they are not converted by another thread's changes.
 *   Native exempt-handler mask edits racing with wait entry also lack full
 *   logical-mask guarantees. Ordinary kernel FD readiness changes still work.
 * - For default/ignored SIGSEGV/SIGBUS, native temporary-mask waits do not
 *   guarantee exact pending/forwarding/replay order for asynchronous injections
 *   or hide hook-only interruptions. Eligible protected-memory faults remain
 *   intercepted with temporary fault-only inhibition too. Custom original fault
 *   handlers retain full temporary-mask emulation.
 *
 * @section overlaysys_ownership Thread, process, and FD ownership
 * Shared-VM clone children require the same thread group, shared dispositions,
 * independent TLS, and a separate stack. Unsupported clone modes and
 * intercepted vfork fail with EOPNOTSUPP. Fork snapshots are serialized before
 * callbacks; dispatch inheritance is described by
 * overlaysys_clone_child_epilogue_t.
 *
 * FD tracking follows descriptor-table sharing/copying within an address space.
 * External changes to shared signalfd/epoll descriptions and unobserved FD
 * transfers are not mirrored. unshare(CLONE_FILES) and
 * close_range(CLOSE_RANGE_UNSHARE) work in synchronous code, including syscall
 * hooks, but must not run in signal hooks or application signal handlers. This
 * is a caller requirement, not a runtime rejection. Multiple callback consumers
 * still need to coordinate FD ownership and signal policies.
 *
 * @section overlaysys_host Host requirements
 * The host must permit internal syscalls and required /proc access. User-memory
 * copies need process_vm_writev or pipe2/read/write/close; retained ordinary
 * epoll events need readable /proc/thread-self/fdinfo; nonzero timeouts need a
 * working monotonic clock through vDSO or clock_gettime. Registry resizing also
 * reads /proc/self/maps to validate its backing FD. Kernel restrictions apply.
 */

#pragma once

#ifdef __cplusplus
#include <type_traits>
#endif

#include <x86linux/helper.h>

/** @brief Owned asynchronous signal information for caller-controlled replay.
 */
typedef struct sigctx sigctx_t;

/* Optional parameters carry nullability annotations; others remain implicit. */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup overlaysys_registration Hook and epilogue registration
 * @brief Five ordered callback lists shared by fork descendants.
 *
 * Lists start empty and run in index order. Syscall/signal chains stop at
 * forward = 0; eligible syscall/clone epilogues all run. Indices are per list:
 * insertion/removal shifts later entries up/down, so a returned position may
 * change before the caller resumes. See overlaysys_hook_insert for duplicate
 * and replacement rules. Registration does not activate patching or signal
 * policies; empty lists do not disable internal emulation.
 *
 * @par Lifetime and sharing
 * A constructor creates MAP_SHARED lists, nodes, allocation metadata, and a
 * process-shared mutex before any registration. Fork descendants share changes
 * in both directions, even if fork precedes the first insert. Independent loads
 * and exec do not join; process exit leaves surviving lists intact. Callback
 * addresses are unchanged: code/state must remain valid in every participant.
 * No library reference is retained or state copied; replacement/removal/clear
 * neither free state nor unload code. Signal/emulation policies are not shared
 * by this registry.
 *
 * @par Synchronization
 * One mutex serializes registry operations, including reads, allocation,
 * relocation, and compaction. Dispatch takes no registration lock. During
 * mutation, callers must stop traversal/callback execution and prevent dispatch
 * (including signals and fork/clone) across all sharing processes. These APIs
 * neither wait for callbacks nor stop threads; keep code/state alive until
 * caller-established quiescence. Registry APIs are not async-signal-safe: never
 * call from signal handlers or hooks/epilogues. Local checks cannot detect
 * other active processes, threads, or frames. Queries may run alongside stable
 * dispatch; each is a snapshot, and separate queries may observe different
 * registrations.
 *
 * @par Storage
 * A memfd starts at one page and grows before new nodes are mapped. Mappings
 * may relocate; links tolerate different process-local bases. Removal compacts
 * nodes across all lists and attempts to shrink mappings and backing size to
 * page-rounded live storage: at least one data page plus a fixed control page.
 * Other processes refresh on their next registry API call or dispatch. Refresh
 * briefly blocks physical signals and serializes remapping within each address
 * space; normal dispatch needs no remapping syscall. Tail-page reclamation also
 * frees backing pages of idle peers retaining larger mappings. Reclamation and
 * shrinking are best effort; OS failures do not undo removal.
 *
 * Capacity is bounded by page-rounded PTRDIFF_MAX and the initial RLIMIT_FSIZE;
 * allocations also depend on memory/address/file-size limits. A private CLOEXEC
 * FD, inherited across fork, allows growth without extra capabilities and
 * follows each FD table. Intercepted close/close_range preserve it; dup2/dup3
 * relocate it before replacement. Raw FD operations must not close or replace
 * library-owned descriptors. If this happens before interception, growth fails
 * with EBADF or ESTALE without truncating a replacement file.
 *
 * @par Common errors
 * Invalid arguments set EINVAL; detected callback-context use sets EDEADLK.
 * Constructor failure is cached without retry or private fallback;
 * calls before it runs report ENODEV, and an initial RLIMIT_FSIZE smaller than
 * one page reports EFBIG. Initialization, mutex, and mapping-refresh failures
 * leave registrations unchanged: insert returns -1, remove returns NULL, and
 * clear returns -1 with errno set. Exhausted capacity reports ENOMEM; other
 * system errors propagate. Missing hook get/remove entries set ENOENT.
 * Successful calls, including empty clears, preserve errno. Failure to restore
 * a temporary physical signal mask or map enough storage for dispatch is fatal.
 * Mutex ownership is not recovered after a process dies during mutation.
 * @{
 */

/**
 * @brief Intercept a syscall before required internal emulation.
 * @param num Kernel syscall number.
 * @param a,b,c,d,e,f First through sixth kernel arguments, respectively.
 * @param[in,out] forward Non-NULL flag, initially 1; set to 0 to replace the
 * call, skipping remaining syscall hooks and this call's internal emulation.
 * @return Replacement result when *forward is 0; otherwise ignored.
 *
 * Return -1 with errno for a replacement error; incidental errno changes do not
 * affect forwarded calls. If a nested call completes the operation, return its
 * result with *forward = 0 to avoid duplicate execution.
 *
 * Direct intercepted calls from hooks/epilogues skip user syscall hooks and
 * epilogues but retain signal/FD/lifecycle emulation. Signal hooks remain
 * active; original handlers use inherited application dispatch.
 *
 * @warning At first interception depth, forward = 0 bypasses internal emulation
 * even in patched code, with no later reconciliation in either PEDANTIC mode.
 * Replacing tracked effects can desynchronize signal actions/masks, pending or
 * signalfd/epoll state, FD aliases, or clone ownership. Leave forward nonzero
 * or perform the operation through intercepted nested calls before consuming
 * it; raw _overlaysys_syscall() does not preserve bookkeeping. Rejection
 * without effects or replacement needing no tracked-state handling is allowed;
 * syscall names and plausible return values alone do not establish safety.
 *
 * @par Required intercepted syscalls
 * Keep the following kernel syscalls on the intercepted path; SYS_ is omitted:
 * - Lifecycle: clone, clone3, fork, vfork, exit.
 * - Signals: rt_sigaction, rt_sigprocmask, rt_sigpending, rt_sigtimedwait,
 *   rt_sigsuspend, sigaltstack.
 * - Signalfd I/O: signalfd, signalfd4, read, readv.
 * - Epoll: epoll_create, epoll_create1, epoll_ctl, epoll_wait, epoll_pwait,
 *   epoll_pwait2.
 * - FD management: close, close_range, dup, dup2, dup3, fcntl, unshare.
 * - Other I/O waits: poll, select, ppoll, pselect6.
 *
 * @pre Do not bypass required handling with raw or unpatched instructions.
 * Intervention depends on arguments and tracked state; unrelated operations
 * stay native. Intercepted vfork fails with EOPNOTSUPP.
 */
typedef long (*overlaysys_syscall_hook_t)(long num, long a, long b, long c,
                                          long d, long e, long f,
                                          int *restrict forward);

/**
 * @brief Observe or change a completed, forwarded syscall's result.
 * @param num Original kernel syscall number.
 * @param a,b,c,d,e,f First through sixth original kernel arguments,
 * respectively.
 * @param[in,out] orig_ret Non-NULL result pointer including preceding
 * epilogues' changes; borrowed only for this callback, never retained.
 *
 * Runs in order after every hook forwards and the syscall returns normally in
 * its original context, including internal emulation. Excludes replaced or
 * nonreturning calls, suppressed/disabled or nested user dispatch, and all
 * clone/clone3/fork/vfork/rt_sigreturn paths. Callbacks must return normally;
 * nested calls follow overlaysys_syscall_hook_t's emulation rules.
 *
 * @par Results and errno
 * Input uses libc form: raw errors in [-4095, -1] become *orig_ret = -1 with
 * positive errno; success sets errno to zero. Leave the result unchanged to
 * pass through, or store a success value to replace/recover it. To report an
 * error, store -1 and set errno to a native code in [1, 4095], such as EACCES;
 * invalid errno becomes EINVAL. Raw negative errors such as -EACCES are not
 * supported outputs. Only *orig_ret == -1 uses errno: preserve it across
 * logging or other calls to retain an incoming failure; other errno changes are
 * ignored. Only the final error updates application errno. Recovery to success
 * retains prior application errno, including original-handler changes.
 *
 * @warning Result changes do not undo the operation or its bookkeeping; visible
 * effects must remain consistent with the consumer's contract.
 */
typedef void (*overlaysys_syscall_epilogue_t)(long num, long a, long b, long c,
                                              long d, long e, long f,
                                              long *restrict orig_ret);

/**
 * @brief Borrowed action and continuation state shared by one signal chain.
 * Every hook sees the same record, including changes from manual orig_handler
 * calls. Do not retain this record or its continuation beyond this invocation.
 */
typedef struct extsiginfo {
  /**
   * @brief Dispatch this invocation's selected original action.
   * @param sig Signal number supplied to the signal hook.
   * @param info Signal information supplied to the signal hook.
   * @param ucontext Writable context supplied to the signal hook.
   * @pre Call only inside the current signal hook with its supplied arguments.
   *
   * Each continuation call dispatches again without changing forward or
   * skipping later hooks; automatic forwarding may dispatch once more after
   * hook return. Manual calls are allowed even with inhibit_orig. SIG_IGN and
   * default-ignore/continue do nothing.
   *
   * Each SA_RESETHAND registration is claimed once per process at dispatch.
   * Losing arrivals take the default action without consuming newer
   * registrations. Further manual calls repeat this invocation's resolved
   * action; automatic forwarding after a manual one-shot dispatch takes the
   * default action.
   */
  void (*orig_handler)(int sig, siginfo_t *restrict info,
                       void *restrict ucontext);
  /**
   * @brief Automatic inhibition snapshot at hook entry.
   * True for deferred or blocked arrivals, SIG_IGN, and default-ignore/continue
   * actions; manual orig_handler calls remain allowed.
   */
  bool inhibit_orig;
  /**
   * @brief Selected action's restart hint, updated by manual dispatch.
   * Read after orig_handler returns. Reflects requested SA_RESTART
   * independently of policy-forced kernel flags; SIG_DFL reports true. Neither
   * proves delivery nor triggers restart: count actual dispatches and honor the
   * syscall's timeout and partial-result rules. See @ref overlaysys_waits.
   */
  bool restartable;
} extsiginfo_t;

/**
 * @brief Handle each intercepted arrival and valid pending replay.
 * @param sig Delivered signal number.
 * @param[in,out] info Non-NULL signal information for this invocation.
 * @param[in,out] ucontext Non-NULL writable kernel signal context.
 * @param[in,out] forward Non-NULL flag, initially 1; nonzero continues the
 * chain and permits automatic delivery/pending publication according to
 * captured blocking/disposition state. Zero stops both after hook return.
 * @param extra Non-NULL borrowed continuation state for this invocation.
 * Manual extra->orig_handler calls are independent of forward. Deferred/blocked
 * decisions stay hidden in per-signal order until hook return; waiting for the
 * current hook's own decision cannot progress. Otherwise, a dispatched
 * application handler may leave nonlocally.
 *
 * The hook's own signal is deferred until original self-deferral is restored
 * for the application handler; other hook mask changes apply there. The final
 * mask comes from ucontext.uc_sigmask. The errno rules in
 * @ref overlaysys_context apply.
 *
 * @pre Observe the signal-context FD restrictions in @ref overlaysys_ownership.
 * @see extsiginfo_t
 * @see overlaysys_sig_set_defsighand
 */
typedef void (*overlaysys_sig_hook_t)(int sig, siginfo_t *restrict info,
                                      void *restrict ucontext,
                                      int *restrict forward,
                                      const extsiginfo_t *restrict extra);

/**
 * @brief Append the current eligible signal to a caller-selected queue.
 * @param[in,out] queue Owned queue head, initially NULL; unchanged on failure.
 * @retval 0 Success. Set the hook's forward flag to zero to defer delivery.
 * @retval -1 Failure with errno; no signal has been captured.
 *
 * Copies siginfo and the eligible delivery mask, not borrowed ucontext or
 * handler-continuation pointers, using private raw mappings without libc
 * allocation. Call only from the current
 * signal hook before original-handler dispatch. Synchronous hardware faults
 * are rejected with EOPNOTSUPP; inhibited arrivals with EAGAIN, repeat capture
 * with EALREADY, and invalid context/arguments with EINVAL. Other system errors
 * propagate. Success preserves errno.
 *
 * The caller selects its queues and safe replay points. Each head must have
 * exclusive ownership; do not copy it to create another owning queue. Queue
 * links remain opaque. This call appends before restoring the physical signal
 * mask, allowing a nested hook to append safely to the same queue. Use an
 * atomic pointer load when checking a head shared with the signal hook.
 * Captures make
 * OverlaySys-managed waits return EINTR rather than swallow the interruption;
 * they do not interrupt unrelated raw kernel waits or run handlers themselves.
 * The creating thread owns the queue until submit or release. Wrong-thread or
 * stale heads fail with EPERM. Outstanding records disappear at thread exit
 * and are not inherited by fork children; child callbacks must reset their
 * copied heads to NULL.
 */
int overlaysys_sig_capture(sigctx_t *_Nullable *restrict queue) noexcept;

/**
 * @brief Take and dispatch a selected queue at a caller-selected safe point.
 * @param[in,out] queue Owned queue head; cleared before any application
 * handler.
 * @retval 0 The selected queue was delivered or discarded by current
 * dispositions; an empty queue is a no-op.
 * @retval -1 Failure with errno. A non-NULL head retains the entire unsubmitted
 * queue. NULL means OverlaySys owns any remaining occurrences and cleanup.
 *
 * Preparation is all-or-nothing. The whole queue transfers before the first
 * handler, without consuming other caller-owned queues. Nested submissions
 * dispatch their own batch, not an outer batch; remaining outer occurrences
 * follow ordinary pending-mask rules during a handler. No caller-owned queue
 * or active-scope flag is retained across application callbacks or nonlocal
 * exits. Call after releasing consumer locks and references that would block
 * reentrant application operations.
 *
 * Replay uses the current disposition and alternate stack with the captured
 * eligible delivery mask and a fresh kernel signal frame. This preserves
 * eligibility when a temporary pselect/ppoll mask has already been restored.
 * It invokes the signal-hook chain again, so actual
 * handler delivery and its restart decision are observed there. Original
 * register/stack snapshots are not replayed. Standard signals coalesce and
 * realtime signals retain per-signal capture order within the queue under
 * normal pending
 * rules. Installing an ignored disposition discards pending occurrences.
 *
 * The application logical return mask, including handler edits, is restored;
 * a consumer's temporary raw physical blocking does not become that mask.
 * Submission from a signal hook returns EDEADLK; wrong process/thread returns
 * EPERM, NULL queue arguments return EINVAL, and other system errors propagate.
 * Success preserves errno. The caller must prevent recursive recapture when
 * it chooses to submit; it must not release transferred records.
 */
int overlaysys_sig_submit(sigctx_t *_Nullable *restrict queue) noexcept;

/**
 * @brief Take and discard a queue without invoking application handlers.
 * @param[in,out] queue Owned queue head, cleared upon takeover; NULL or an
 * empty queue is a no-op.
 * @note Success preserves errno. Failure sets errno; a non-NULL head remains
 * caller-owned, while NULL transfers cleanup to OverlaySys. A failed mask
 * restoration may leave physical signals blocked.
 */
void overlaysys_sig_release(
    sigctx_t *_Nullable *_Nullable restrict queue) noexcept;

/**
 * @brief Run in a child after fork/clone state and configured altstack setup.
 * New threads/children on a new stack inherit the creator's syscall-hook
 * participation; creation inside a hook/epilogue suppresses user syscall hooks
 * in that child and its descendants. Fork resumes the copied context with
 * inherited dispatch state. Signal hooks remain active.
 * Epilogues run in order with interception state installed and cannot cancel
 * the completed clone. Failed clones have no child epilogue. Each callback
 * enters with errno = 0; incidental changes are discarded.
 * @see @ref overlaysys_ownership
 */
typedef void (*overlaysys_clone_child_epilogue_t)(void);

/**
 * @brief Run in the parent after fork/clone completion or rejection.
 * @param child_tid Child ID on success or raw negative errno on failure,
 * including clone/clone3 arguments rejected before kernel execution.
 * @note Before each callback, errno is set to zero on success or -child_tid on
 * failure. Incidental errno changes are discarded.
 */
typedef void (*overlaysys_clone_parent_epilogue_t)(pid_t child_tid);

/**
 * @brief Select one independently indexed callback list.
 * @note The handler signature must match the selected type. The C ABI stores
 * function pointers as void pointers, using the supported Linux x86-64 ABI;
 * implicit conversion in C is a GNU extension and may trigger -Wpedantic.
 * C++ insertion accepts typed callbacks with the same argument order; removal
 * returns void * in both languages.
 */
typedef enum {
  OVERLAYSYS_HOOK_TYPE_SYSCALL,          /**< overlaysys_syscall_hook_t */
  OVERLAYSYS_HOOK_TYPE_SYSCALL_EPILOGUE, /**< overlaysys_syscall_epilogue_t */
  OVERLAYSYS_HOOK_TYPE_SIG,              /**< overlaysys_sig_hook_t */
  OVERLAYSYS_HOOK_TYPE_CLONE_CHILD_EPILOGUE,  /**<
                                                 overlaysys_clone_child_epilogue_t
                                               */
  OVERLAYSYS_HOOK_TYPE_CLONE_PARENT_EPILOGUE, /**<
                                                 overlaysys_clone_parent_epilogue_t
                                               */
} overlaysys_hook_type_t;

/**
 * @brief Register a callback in the selected list.
 * @param type Declared overlaysys_hook_type_t value selecting the list.
 * @param handler Non-NULL callback matching type.
 * @param idx Position from 0 through this list's length, or -1 for the end.
 * @param replace For a new address, true replaces an existing position without
 * allocating a node, growing storage, or changing length/order; false inserts
 * before it. Both append at the end.
 * @return Existing, inserted, or replaced zero-based index; appending returns
 * the previous length. Success preserves errno.
 * @retval -1 Failure with errno set: EINVAL for invalid type/handler/index;
 * ENOMEM for exhausted capacity/allocation; other overlaysys_registration
 * errors propagate without changing registrations.
 * @pre The C ABI cannot validate handler signatures; the caller must match
 * type. The lifetime/context/synchronization rules of overlaysys_registration
 * apply.
 * @note After argument validation, an address already in this list returns its
 * existing index without a new node or list changes, even if replace is true
 * and idx names another position. Other lists are independent.
 */
ptrdiff_t overlaysys_hook_insert(overlaysys_hook_type_t type,
                                 void *restrict handler, ptrdiff_t idx,
                                 bool replace) noexcept;

/**
 * @brief Return one callback without changing its registration.
 * @param type Declared overlaysys_hook_type_t value selecting the list.
 * @param idx Zero-based position in this list, or -1 for its last entry.
 * @return Registered handler preserving errno, or NULL with errno on failure:
 * ENOENT for a missing entry (including -1 on an empty list), EINVAL for
 * invalid type or idx below -1. Other overlaysys_registration errors propagate.
 * @note Returns a snapshot without retaining a registration/library reference
 * or changing shared links. Keep code/state alive until use finishes, even
 * after removal/replacement. The query/context rules of overlaysys_registration
 * apply.
 * @see overlaysys_registration
 */
void *overlaysys_hook_get(overlaysys_hook_type_t type, ptrdiff_t idx) noexcept;

/**
 * @brief Remove and return one callback.
 * @param type Declared overlaysys_hook_type_t value selecting the list.
 * @param idx Zero-based position in this list, or -1 for its last entry.
 * @return Removed handler preserving errno, or NULL with errno on failure;
 * cast non-NULL results to the signature for type. Missing-entry and validation
 * errors match overlaysys_hook_get; other overlaysys_registration errors
 * propagate. Failure leaves registrations unchanged.
 * @pre Follow overlaysys_registration's lifetime and synchronization rules;
 * removal neither waits for callbacks nor releases their code/state.
 * @see overlaysys_registration
 */
void *overlaysys_hook_remove(overlaysys_hook_type_t type,
                             ptrdiff_t idx) noexcept;

/**
 * @brief Remove every callback from the selected list.
 * @param type Declared overlaysys_hook_type_t value selecting the list.
 * @retval 0 Success, including an empty list; errno is preserved.
 * @retval -1 Failure with errno set; the list is unchanged. Invalid type sets
 * EINVAL; common registration errors propagate.
 * @note Other lists, signal policies, pending signals, and internal emulation
 * are unchanged. Reclamation is best effort; callbacks are not waited for.
 * @see overlaysys_registration
 */
int overlaysys_hook_clear(overlaysys_hook_type_t type) noexcept;

/**
 * @brief Copy the canonical absolute path of one callback's loaded image.
 * @param type Declared overlaysys_hook_type_t value selecting the list.
 * @param idx Zero-based position in this list, or -1 for its last entry.
 * @param[out] ptr Caller-owned buffer; NULL allowed only with zero capacity.
 * @param capacity Buffer size in bytes, including the terminating NUL.
 * @retval 0 Complete NUL-terminated result; errno is preserved. An absent entry
 * produces an empty string; a registered address with no known image/path
 * produces "?". Main-executable callbacks are included.
 * @retval -1 Failure with errno set. Insufficient capacity sets ENOMEM after
 * copying the first capacity - 1 bytes and a NUL when capacity is nonzero.
 * Zero capacity always fails with ENOMEM for an otherwise valid query. Other
 * errors leave the buffer empty when ptr is non-NULL and capacity is nonzero.
 *
 * Paths are resolved from the actual mapped image and canonicalized, including
 * symlink resolution. A relative dlopen path remains resolvable after chdir.
 * No library reference or return buffer is retained; copied results are
 * independent of the image afterward. Lookup neither activates interception nor
 * patches/loads images, changes membership/shared links, or adds dispatch work.
 * @pre Keep loader mappings/backing files stable; follow
 * overlaysys_registration query/context rules. Queries refresh this process's
 * mapping under the mutex.
 * @par Errors
 * Invalid type, index below -1, or NULL ptr with nonzero capacity sets EINVAL;
 * allocation/path-resolution and common overlaysys_registration errors
 * propagate.
 * @see overlaysys_hook_get_libname
 * @see overlaysys_hook_get_name
 */
int overlaysys_hook_get_libpath(overlaysys_hook_type_t type, ptrdiff_t idx,
                                char *restrict ptr, size_t capacity) noexcept;

/**
 * @brief Copy the filename of one callback's loaded image.
 * @param type Declared overlaysys_hook_type_t value selecting the list.
 * @param idx Zero-based position in this list, or -1 for its last entry.
 * @param[out] ptr Caller-owned buffer; NULL allowed only with zero capacity.
 * @param capacity Buffer size in bytes, including the terminating NUL.
 * @param exclude_extension Remove the last dot and its suffix, unless it is the
 * leading dot: .hidden is unchanged; libfoo.so.1 becomes libfoo.so.
 * @retval 0 Complete NUL-terminated filename; errno is preserved.
 * @retval -1 Failure with errno set.
 *
 * Uses the canonical path's basename. Absence, unknown images, truncation,
 * errors, ownership, and calling rules follow overlaysys_hook_get_libpath.
 * @see overlaysys_hook_get_libpath
 */
int overlaysys_hook_get_libname(overlaysys_hook_type_t type, ptrdiff_t idx,
                                char *restrict ptr, size_t capacity,
                                bool exclude_extension) noexcept;

/**
 * @brief Copy the symbol or debug-information name of one registered callback.
 * @param type Declared overlaysys_hook_type_t value selecting the list.
 * @param idx Zero-based position in this list, or -1 for its last entry.
 * @param[out] ptr Caller-owned buffer; NULL allowed only with zero capacity.
 * @param capacity Buffer size in bytes, including the terminating NUL.
 * @retval 0 Complete NUL-terminated name; errno is preserved. An absent entry
 * produces an empty string; a registered address with no known name produces
 * "?". Missing symbols are not errors.
 * @retval -1 Failure with errno set; overlaysys_hook_get_libpath's buffer,
 * truncation, error, and ownership rules apply. Symbol-resolution errors also
 * propagate.
 *
 * Lookup checks full/dynamic ELF symbols and elfutils debug sources, including
 * local/static functions, separate build-ID/.gnu_debuglink files, compressed
 * .gnu_debugdata, and DWARF subprogram names with abstract-origin/specification
 * references. Configured DEBUGINFOD_URLS and local caches may also be used.
 * Names are not demangled; unavailable optional debug information falls back to
 * remaining sources. No resolver state is retained.
 * @pre Follow overlaysys_hook_get_libpath's loader/context rules. Backing ELF
 * files must match their loaded images and stay unchanged. Query serialization
 * covers resolution and copying.
 * @see overlaysys_hook_get_libpath
 */
int overlaysys_hook_get_name(overlaysys_hook_type_t type, ptrdiff_t idx,
                             char *restrict ptr, size_t capacity) noexcept;

/** @} */

/**
 * @brief Patch the union of loaded shared libraries matching paths.
 * @param len Number of entries; zero selects no objects but prepares the
 * runtime.
 * @param paths Read-only array of len nonempty paths/patterns; NULL allowed for
 * zero len. Basenames select all matches; './name' selects a current-directory
 * file. Arrays and strings must be valid C objects.
 * @param skip_missing Skip missing files/unmatched entries if true; otherwise
 * every entry must match an eligible loaded object.
 * @retval 0 All selected objects completed; errno is preserved.
 * @retval -1 Failure with the first errno; applied changes are not rolled back.
 * @pre The lifecycle and path-selection rules of overlaysys_patch_all apply.
 *
 * Entries are validated separately; overlapping matches are processed once.
 * Required matches are checked before text changes; completed instances satisfy
 * matching. Any match against OverlaySys's image is rejected, including
 * wildcard matches with skip_missing. Wildcards may skip other protected
 * objects if they also match eligible ones. No libraries are loaded implicitly.
 *
 * @par Retry and ownership
 * Completed objects are skipped. Retry first finishes failed cleanup, then
 * rebuilds preparation. Written code, trampolines, metadata, and loader
 * references remain alive; failed RX restoration leaves completion false and
 * may leave pages writable. Retry then only restores protection. Earlier batch
 * successes remain active; selected library references/registry entries may
 * survive failure. Keep affected code inactive until retry completes.
 *
 * @par Errors
 * EINVAL: invalid arguments/options; ENOENT: required match missing; EPERM:
 * protected target, including any wildcard matching OverlaySys; ENOMEM:
 * allocation failure; ENOEXEC: invalid ELF; EOPNOTSUPP: unsupported layout or
 * decoder mode; EOVERFLOW/ERANGE: size or branch range; ESTALE: changed
 * mapping; EBUSY/EDEADLK: concurrent/reentrant use. Other system errno values
 * propagate; loader failures without an errno classification use EIO/ELIBACC.
 * Capstone errors map to errno. Reported failures do not terminate the process.
 * @see overlaysys_patch_all
 */
int overlaysys_patch(size_t len, const char *const *restrict paths,
                     bool skip_missing) noexcept;

/**
 * @brief Patch the shared libraries loaded in this linker namespace.
 * @param len Number of exclusions; zero selects all eligible loaded libraries.
 * @param inhibit_patch Read-only array of len nonempty paths/patterns; NULL
 * allowed for zero len. Matches are skipped for this call; missing/unmatched
 * exclusions are ignored.
 * @retval 0 All nonexcluded objects completed processing; errno is preserved.
 * @retval -1 Failure with errno; overlaysys_patch's irreversible
 * retry/ownership and error rules apply.
 *
 * @par Path selection
 * Names without '/' match loader-recorded basenames, including leading dots;
 * paths with '/' identify absolute files or files relative to the current
 * working directory. Only '*' is special: it matches zero or more bytes within
 * one component; '**' is not recursive. Filesystem patterns require explicit
 * leading dots and select loaded regular files by device/inode, so hard links
 * and symlinks share identity. Wildcards ignore nonregular files/dangling
 * links. Exclusions may match protected objects. No unloaded libraries are
 * searched through LD_LIBRARY_PATH or loaded implicitly.
 *
 * @pre First activation must precede thread creation and tracked signal/FD
 * relationships, including in earlier constructors: existing threads and FD
 * relationships are not adopted. Load initial targets, register hooks, patch
 * successfully, then start workers. Loading OverlaySys alone never patches
 * code; existing handlers/SIG_IGN remain native.
 * @pre Finish target loading/constructors and keep affected code inactive and
 * loader mappings stable through patching/retry. No thread may execute or
 * resume into rewritten bytes, including through return addresses, signal
 * handlers, or saved contexts; pausing inside affected code is insufficient.
 * Never patch from a signal handler. EBUSY/EDEADLK checks serialize API calls,
 * not execution; arbitrary multithreaded live patching is unsupported.
 *
 * Completed instances stay unchanged; exclusions neither undo patches nor
 * prevent later selection. Newly loaded libraries need another call. Selected
 * objects are retained until exit, preventing dlclose unloading/final
 * destructors. Protected objects are the main executable, OverlaySys/its
 * engine, vDSO, and decoder runtime. OverlaySys's image is identified by
 * implementation address and loader mapping regardless of filename, and always
 * skipped. Other linker namespaces are excluded. Backing ELF must stay
 * readable/unchanged and match mappings; supported executable sections lie in
 * one readable, non-writable executable load segment.
 * Anonymous/generated/modified code is not discovered automatically. Success
 * covers selected objects, not every process syscall.
 *
 * @par Errors
 * Only input-resolution ENOENT/ENOTDIR or no loaded match counts as missing;
 * a selected object's missing backing ELF is an error. Other lookup,
 * initialization, patch, and cleanup errors propagate. Cleanup is attempted;
 * kernel-denied mask/protection/resource restoration can leave partial state.
 * Environment options are validated before applying them; invalid values may be
 * corrected and retried. Once their application starts, retries retain
 * validated options and finish remaining initialization stages.
 * @see overlaysys_patch
 */
int overlaysys_patch_all(size_t len,
                         const char *const *restrict inhibit_patch) noexcept;

/**
 * @brief Query completion for all loaded libraries selected by path.
 * @param path Nonempty basename/file/'*' pattern using overlaysys_patch_all's
 * rules; NULL selects all eligible libraries in this linker namespace.
 * @param[out] check Non-NULL writable result, assigned only on success. True
 * if all selected instances completed; a non-NULL path must match at least one
 * eligible instance. A NULL path also yields true for an empty eligible set.
 * False for no eligible non-NULL match, an unpatched instance, or an exact
 * protected target. These are successful queries, not errors.
 * @retval 0 Query completed; *check is set and errno is preserved.
 * @retval -1 Failure with errno; *check is unchanged.
 *
 * Wildcards ignore protected objects; missing files yield false. Successfully
 * processed objects without syscall instructions count too. Later dlopen may
 * add unpatched matches. Queries read completion records, not instruction
 * integrity, without initializing, patching, loading, or retaining libraries.
 *
 * @pre Call where libc allocation/loader operations are safe, including
 * suitable ordinary hooks; never in signal handlers or allocator/loader
 * critical sections. Serialize all patch/query calls and keep loader mappings
 * stable. Queries conflicting with an active patch or query return EBUSY.
 * @par Errors
 * EINVAL: NULL check, empty path, or invalid file type. Operational lookup and
 * signal-mask errors propagate; cleanup preserves the first error.
 * Interception state is restored before return. A failed physical signal-mask
 * restoration is reported and may leave signals blocked. Reported failures do
 * not terminate the process.
 * @see overlaysys_patch
 */
int overlaysys_patch_check(const char *restrict path,
                           bool *restrict check) noexcept;

/**
 * @brief Prepare immutable function ranges and unwind rules for stack queries.
 * @retval 0 Preparation completed; errno is preserved.
 * @retval -1 Failure with errno; previously published metadata stays usable.
 * @pre Run outside hooks and signal handlers with loader mappings stable,
 * before workers start or after externally quiescing loading and patching.
 * Preparation may allocate, use the loader, and inspect ELF files. Loaded
 * libraries and published metadata are retained until process exit; repeating
 * this call adds newly loaded instances without changing existing records.
 * Objects lacking supported symbols or unwind information remain unknown to
 * the query. Later-loaded objects require another preparation call.
 * Backing ELF files must remain readable and match their loaded instances.
 * @see overlaysys_callstack_check
 */
int overlaysys_callstack_prepare(void) noexcept;

/**
 * @brief Check the calling thread's physical stack for a prepared function.
 * @param func_ptr Entry address of an ELF function with a known nonempty code
 * range. PLT stubs, unresolved IFUNC resolvers, and arbitrary interior
 * addresses are not substitutes for the implementation's function entry.
 * @param[out] on_callstack Non-NULL writable result, assigned only on success.
 * True means a frame in the function's prepared code range was found; false
 * means supported unwinding reached the end without finding one.
 * @retval 0 Query completed; *on_callstack is set and errno is preserved.
 * @retval -1 Unknown or failed query with errno; *on_callstack is unchanged.
 *
 * The query uses immutable prepared metadata and per-call stack storage, with
 * no heap allocation, loader access, logging, or shared-lock wait. Stack reads
 * use direct process_vm_readv syscalls; the host must permit them. Ordinary
 * syscall hooks resume inspection from the wrapper's original syscall context.
 * The query's own frames are omitted. Resolve the caller's dynamic binding to
 * this entry point before invoking it from hooks, for example with eager
 * binding or an initial call in ordinary startup code.
 * Inline/tail-eliminated frames and unrecorded discontiguous function portions
 * are not recovered. Absence does not prove that reentry is safe: other
 * functions may share the same locks or state.
 *
 * Keep prepared code and loader mappings unchanged. New/unsupported frames,
 * incomplete unwind data, invalid memory, and traversal limits report failure
 * rather than absence. A non-NULL output must designate a writable bool.
 * Errors include EINVAL for NULL arguments, ENODATA for unavailable metadata
 * (including rules that could not be prepared), EOPNOTSUPP for unsupported
 * operations in a prepared rule, ELOOP/EOVERFLOW for traversal limits, and the
 * kernel's memory-read errors. Published metadata is never freed by a query.
 * @see overlaysys_callstack_prepare
 */
int overlaysys_callstack_check(const void *restrict func_ptr,
                               bool *restrict on_callstack) noexcept;

/**
 * @brief Explicitly initialize and patch all eligible loaded libraries.
 * @return The 0/-1 result of overlaysys_patch_all; failure sets errno.
 * @pre The calling rules of overlaysys_patch_all apply.
 * @see overlaysys_patch_all
 */
#define OVERLAYSYS_INIT() overlaysys_patch_all(0, NULL)

/**
 * @brief Explicitly initialize and patch libc.so* and libpthread.so*.
 * Missing libraries are skipped.
 * @return The 0/-1 result of overlaysys_patch; failure sets errno.
 * @note This is an expression macro for the supported GNU C/C++ toolchains.
 * @pre The calling rules of overlaysys_patch apply.
 * @see overlaysys_patch
 */
#define OVERLAYSYS_INIT_LIBC()                                                 \
  ({                                                                           \
    const char *const init_paths[] = {"libc.so*", "libpthread.so*"};           \
    overlaysys_patch(2, init_paths, true);                                     \
  })

/**
 * @brief Update independent default-action interception and blocking policies.
 * @param force_hook Signals whose SIG_DFL actions should be intercepted.
 * @param inhibit_block Signals whose SIG_IGN actions and kernel blocking should
 * be overridden. Use both policies to intercept blocked SIG_DFL signals.
 * @retval 0 Success, including both arguments NULL before initialization.
 * @retval -1 Failure; errno identifies the first error.
 * @pre Inputs are valid sigset_t objects or NULL, may alias, and are not
 * modified. Each non-NULL set replaces its policy; NULL preserves it. Empty
 * sets clear policies except for environment-forced bits below.
 *
 * Logical queries retain requested actions/flags/masks; wrapped actions use
 * SA_SIGINFO internally. Ignored arrivals call only hooks; forwarded blocked
 * arrivals remain pending. Overrides cover sigaction masks and per-thread
 * temporary wait masks; return masks retain syscall/signal-context semantics.
 *
 * Unblocking replays through current actions/hooks. sigwait* and signalfd
 * consume pending records without automatic dispatch; sigpending/FD readiness
 * include them. Forwarded standard arrivals coalesce with the first siginfo;
 * consumed arrivals preserve earlier records. Realtime records retain
 * per-signal FIFO. Installing SIG_IGN/default-ignore discards older records;
 * clearing policies keeps them. Only the receiving thread can consume its
 * records; they disappear on exit and are not inherited by fork children.
 *
 * Inhibited signals force shared SA_RESTART while ignored or logically blocked
 * by any tracked thread; otherwise requested flags apply. Actions and the
 * caller's kernel mask update immediately; other threads refresh on later
 * mask/signal paths. Hooks are not guaranteed while their kernel masks block
 * delivery; no synchronous group-wide refresh occurs.
 *
 * Signal numbers with handlers/SIG_IGN at first activation stay exempt after
 * disposition changes, preserving ASan/Valgrind support. SIGKILL, SIGSTOP, and
 * libc-reserved signals are excluded. OVERLAYSYS_DEFSIGHAND is read once during
 * initialization: 1 forces force_hook for all eligible signals; 2 forces both
 * policies. Updates cannot clear these bits; queries report effective policies.
 * When unset, policies follow the API inputs.
 *
 * @par Errors
 * Non-noop calls before runtime preparation fail with ENODEV. Operational
 * failures return -1 with errno without logging/asserting; earlier per-signal
 * changes may remain. Cleanup is attempted but kernel denial can prevent full
 * restoration. Success preserves errno.
 * @see @ref overlaysys_ownership
 * @see @ref overlaysys_waits
 * @see @ref overlaysys_pedantic
 * @see overlaysys_sig_get_defsighand
 */
int overlaysys_sig_set_defsighand(
    const sigset_t *restrict force_hook,
    const sigset_t *restrict inhibit_block) noexcept;

/**
 * @brief Copy a consistent snapshot of the shared signal policies.
 * @param[out] force_hook Destination for force_hook, or NULL to skip it.
 * @param[out] inhibit_block Destination for inhibit_block, or NULL to skip it.
 * @retval 0 Success, including both outputs NULL before initialization.
 * @retval -1 Failure with the first errno; outputs are unchanged.
 * @pre Outputs are valid, nonoverlapping sigset_t objects or NULL.
 * @note Initialization, operational-error, cleanup, and errno-preservation
 * rules follow overlaysys_sig_set_defsighand.
 * @see overlaysys_sig_set_defsighand
 */
int overlaysys_sig_get_defsighand(sigset_t *restrict force_hook,
                                  sigset_t *restrict inhibit_block) noexcept;

/** @brief Thread-local storage backing overlaysys_syscall_gettid(). */
extern __thread
    __attribute((tls_model("initial-exec"))) pid_t _overlaysys_syscall_self_tid;

/** @brief Thread-local storage backing overlaysys_syscall_getpid(). */
extern __thread
    __attribute((tls_model("initial-exec"))) pid_t _overlaysys_syscall_self_pid;

/**
 * @brief Read the calling thread's cached kernel thread ID.
 * @return Cached TID, or zero if uninitialized; always preserves errno.
 * Reads only TLS, without syscalls, initialization, or identity validation.
 * The cache stays zero until runtime preparation assigns it, including after
 * earlier preparation failures. Loading/registering alone does not populate it.
 * Managed hooks/epilogues run after assignment, but nonzero does not prove
 * complete initialization or patch success.
 *
 * Bypassing intercepted fork/clone is outside the runtime contract: fresh TLS
 * leaves zero; copied TLS may retain a stale inherited TID. This getter neither
 * detects nor repairs it. Zero is missing cached state, not a getter error.
 */
static inline pid_t overlaysys_syscall_gettid(void) noexcept {
  return _overlaysys_syscall_self_tid;
}

/**
 * @brief Read the calling thread's cached kernel process (thread-group) ID.
 * @return Cached PID, or zero if uninitialized; always preserves errno.
 * Initialization and intercepted fork/clone requirements are the same as for
 * overlaysys_syscall_gettid(). Threads share a PID value, not its TLS storage;
 * intercepted process creation refreshes the child's PID before callbacks.
 */
static inline pid_t overlaysys_syscall_getpid(void) noexcept {
  return _overlaysys_syscall_self_pid;
}

/**
 * @brief Execute an unpatched syscall with kernel-layout arguments.
 * @param num Kernel syscall number.
 * @param ... Exactly six long arguments after number; supply 0L for unused
 * ones.
 * @return Kernel result on success, or -1 with errno on failure.
 * @pre Do not bypass tracked operations listed for overlaysys_syscall_hook_t.
 * @note This raw path bypasses OverlaySys hooks and required internal
 * emulation.
 */
long _overlaysys_syscall(long num, ...) noexcept;

/**
 * @brief Disable user syscall hooks and epilogues in the calling thread.
 * @return 0 preserving errno, or -1/EOVERFLOW if the nesting limit is reached.
 * Intercepted syscalls retain OverlaySys signal, descriptor, and lifecycle
 * processing; signal hooks and application handlers remain enabled. Syscalls
 * from those handlers inherit this explicit suppression. Each successful
 * disable requires a matching overlaysys_syscall_hook_enable() in the same
 * thread. Nested pairs do not enable an outer disabled scope or override a
 * callback's recursion guard. Neither function initializes interception or
 * changes signal masks. Do not skip the matching enable by longjmp, thread
 * cancellation, or a C++ exception.
 *
 * A fork continuation inherits the outstanding pairs. Children starting on a
 * new stack inherit effective dispatch eligibility, not the parent's scopes,
 * as for children created inside a syscall hook.
 */
int overlaysys_syscall_hook_disable(void) noexcept;

/**
 * @brief End the calling thread's innermost explicit syscall-hook suppression.
 * @return 0 preserving errno, or -1/EINVAL if no matching disable is active.
 * @see overlaysys_syscall_hook_disable
 */
int overlaysys_syscall_hook_enable(void) noexcept;

#ifdef __cplusplus
}

/**
 * @brief Register a typed C++ callback in the C API's argument order.
 * @tparam Handler Deduced handler type; must convert to at least one supported
 * callback signature. Compatible noexcept functions and noncapturing lambdas
 * are accepted. Requires C++20 or later.
 * @param type Callback list selected at runtime.
 * @param handler Callback whose signature must match the selected type.
 * @param idx Position from 0 through this list's length, or -1 to append.
 * @param replace For a new address, true replaces, false inserts; ends append.
 * @return Existing, inserted, or replaced index, or -1 with errno on failure.
 * A mismatch between type and the handler signature returns -1 with EINVAL.
 * @note The C API's duplicate, validation, lifetime, synchronization, error,
 * and NULL-handler rules apply. An erased void pointer calls the C overload
 * without signature checking. Removal returns void * in both languages.
 * @see overlaysys_hook_insert(overlaysys_hook_type_t, void *, ptrdiff_t, bool)
 */
template <typename Handler>
  requires(std::is_convertible_v<Handler, overlaysys_syscall_hook_t> ||
           std::is_convertible_v<Handler, overlaysys_syscall_epilogue_t> ||
           std::is_convertible_v<Handler, overlaysys_sig_hook_t> ||
           std::is_convertible_v<Handler, overlaysys_clone_child_epilogue_t> ||
           std::is_convertible_v<Handler, overlaysys_clone_parent_epilogue_t>)
inline ptrdiff_t overlaysys_hook_insert(overlaysys_hook_type_t type,
                                        Handler handler, ptrdiff_t idx,
                                        bool replace) noexcept {
  void *addr = nullptr;
  switch (type) {
  case OVERLAYSYS_HOOK_TYPE_SYSCALL:
    if constexpr (std::is_convertible_v<Handler, overlaysys_syscall_hook_t>)
      addr = reinterpret_cast<void *>(
          static_cast<overlaysys_syscall_hook_t>(handler));
    break;
  case OVERLAYSYS_HOOK_TYPE_SYSCALL_EPILOGUE:
    if constexpr (std::is_convertible_v<Handler, overlaysys_syscall_epilogue_t>)
      addr = reinterpret_cast<void *>(
          static_cast<overlaysys_syscall_epilogue_t>(handler));
    break;
  case OVERLAYSYS_HOOK_TYPE_SIG:
    if constexpr (std::is_convertible_v<Handler, overlaysys_sig_hook_t>)
      addr =
          reinterpret_cast<void *>(static_cast<overlaysys_sig_hook_t>(handler));
    break;
  case OVERLAYSYS_HOOK_TYPE_CLONE_CHILD_EPILOGUE:
    if constexpr (std::is_convertible_v<Handler,
                                        overlaysys_clone_child_epilogue_t>)
      addr = reinterpret_cast<void *>(
          static_cast<overlaysys_clone_child_epilogue_t>(handler));
    break;
  case OVERLAYSYS_HOOK_TYPE_CLONE_PARENT_EPILOGUE:
    if constexpr (std::is_convertible_v<Handler,
                                        overlaysys_clone_parent_epilogue_t>)
      addr = reinterpret_cast<void *>(
          static_cast<overlaysys_clone_parent_epilogue_t>(handler));
    break;
  }
  // The common backend rejects invalid types, mismatched signatures, and NULL.
  return overlaysys_hook_insert(type, addr, idx, replace);
}
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif
