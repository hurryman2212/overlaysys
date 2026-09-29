#include <string.h>

#include <sys/mman.h>

#include "internal.h"

enum { SIG_RESET_STATE_SLOTS = 64 };

#define SIG_SS_AUTODISARM (1U << 31)

/*
 * Initialization-configured alternate-stack options.
 */
int sig_enable_sigaltstackautodisarm, sig_enable_sigaltstackeperm;

/*
 * Zero disables automatic alternate-stack allocation.
 */
size_t sig_enable_defsigaltstack;

/*
 * A fork child retains its private copy of this alternate-stack mapping. A new
 * thread has independent TLS and initializes its own signal state and
 * configured stack before application callbacks. Intercepted vfork and unsafe
 * shared-VM clone modes are rejected before they can alias this ownership.
 */
thread_local __attribute((tls_model("initial-exec"))) void *sig_defsigstk;

static _Atomic unsigned long sig_force_sighand;
_Atomic unsigned long sig_inhibit_sigblock;
static int sig_env_sighand;

/* Keep bootstrap emulation until sig_init_env selects the process mode. */
bool sig_pedantic = true;

_Atomic unsigned long sig_wait_sighand;

/*
 * Invocation-local action and continuation state. The signal/info/context tuple
 * identifies the current call; callers must not retain this record or extra.
 *
 * inhibit_orig is the entry snapshot, while restartable can change when the
 * first one-shot dispatch resolves to a different action.
 */
struct sig_call {
  int sig;
  siginfo_t *info;
  void *ctx;
  struct kernel_sigaction action;
  kernel_sigset_t handler_mask, delivery_mask;
  struct sig_reset_state *reset_capture;
  extsiginfo_t extra;
  unsigned long discard_epoch;
  bool captured;
};

static thread_local __attribute((
    tls_model("initial-exec"))) _Atomic(struct sig_call *) sig_current_sig_call;

struct sigctx {
  struct sigctx *next, *previous;
  struct sigctx *queue_next, *queue_tail;
  siginfo_t info;
  kernel_sigset_t delivery_mask;
  unsigned long discard_epoch;
  pid_t pid, tid;
};

/* Consumer-owned captures are not deliverable until explicitly dispatched. */
static thread_local __attribute((
    tls_model("initial-exec"))) _Atomic(struct sigctx *) sig_saved_head;

/* Captures already consumed by submit/release, awaiting mapping cleanup. */
static thread_local
    __attribute((tls_model("initial-exec"))) struct sigctx *sig_retired_head;

bool sig_has_captured(void) {
  return atomic_load_explicit(&sig_saved_head, memory_order_relaxed) != NULL;
}

/* Called with physical signals blocked during thread/fork cleanup. */
static void sig_clear_captured(void) {
  struct sigctx *_saved =
      atomic_exchange_explicit(&sig_saved_head, NULL, memory_order_relaxed);
  while (_saved) {
    struct sigctx *const _next = _saved->next;
    log_verify(!patcher_syscall_err_code(
        internal_raw_munmap(_saved, sizeof(*_saved))));
    _saved = _next;
  }
  while (sig_retired_head) {
    struct sigctx *const _next = sig_retired_head->next;
    log_verify(!patcher_syscall_err_code(
        internal_raw_munmap(sig_retired_head, sizeof(*sig_retired_head))));
    sig_retired_head = _next;
  }
}

/*
 * Written once by setup, before interception or child callbacks are enabled.
 */
static unsigned long sig_exempt_sighand;

static atomic_bool sig_ready;

/*
 * Application-requested mask, including temporary handler/wait masks.
 */
thread_local __attribute((
    tls_model("initial-exec"))) kernel_sigset_t sig_logical_sigmask;

static thread_local
    __attribute((tls_model("initial-exec"))) bool sig_logical_sigmask_inited;

/*
 * Bits removed by the last filter, needed to reconcile a later kernel mask.
 */
static thread_local __attribute((
    tls_model("initial-exec"))) unsigned long sig_suppressed_sigmask;

int sig_raw_rt_sigprocmask(int signum, const kernel_sigset_t *restrict set,
                           kernel_sigset_t *restrict oldset) {
  return util_syscall_no_intercept(SYS_rt_sigprocmask, signum, set, oldset,
                                   sizeof(kernel_sigset_t));
}

/*
 * Block every blockable signal during internal critical sections. Clone keeps
 * it installed through child setup and stages the logical mask separately.
 */
const kernel_sigset_t sig_fset = {
    .__val = {
        [0 ... sizeof_elem(sig_fset, __val) / sizeof_elem(sig_fset, __val, *) -
         1] = (typeof_elem(sig_fset, __val, *))UINT64_MAX}};

static int sig_raw_rt_sigaction(int signum,
                                const struct kernel_sigaction *restrict kact,
                                struct kernel_sigaction *restrict oldkact) {
  return util_syscall_no_intercept(SYS_rt_sigaction, signum, kact, oldkact,
                                   sizeof(kernel_sigset_t));
}

static __always_inline int sig_raw_rt_sigpending(kernel_sigset_t *set) {
  return util_syscall_no_intercept(SYS_rt_sigpending, set, sizeof(*set));
}

static __always_inline int sig_raw_rt_tgsigqueueinfo(pid_t pid, pid_t thread,
                                                     int sig,
                                                     const siginfo_t *info) {
  return util_syscall_no_intercept(SYS_rt_tgsigqueueinfo, pid, thread, sig,
                                   info);
}

/*
 * Linux default actions from signal(7).
 */
enum {
  sig_Term,
  sig_Ign,
  sig_Core,
  sig_Stop,
  sig_Cont,
};

/*
 * Return -1 for unsupported numbers, including libc-reserved signals.
 */
static __attribute((const)) int sig_sigdef(int sig) {
  switch (sig) {
  case SIGALRM:
  case SIGHUP:
  case SIGINT:
  case SIGIO:
    static_assert(SIGIO == SIGPOLL);
  case SIGKILL:
  case SIGPIPE:
  case SIGPROF:
  case SIGPWR:
  case SIGSTKFLT:
  case SIGTERM:
  case SIGUSR1:
  case SIGUSR2:
  case SIGVTALRM:
    return sig_Term;

  case SIGCHLD:
    static_assert(SIGCHLD == SIGCLD);
  case SIGURG:
  case SIGWINCH:
    return sig_Ign;

  case SIGABRT:
    static_assert(SIGABRT == SIGIOT);
  case SIGBUS:
  case SIGFPE:
  case SIGILL:
  case SIGQUIT:
  case SIGSEGV:
  case SIGSYS:
  case SIGTRAP:
  case SIGXCPU:
  case SIGXFSZ:
    return sig_Core;

  case SIGSTOP:
  case SIGTSTP:
  case SIGTTIN:
  case SIGTTOU:
    return sig_Stop;

  case SIGCONT:
    return sig_Cont;
  }

  return likely(sig >= SIGRTMIN && sig <= SIGRTMAX) ? sig_Term : -1;
}

extern const char sig_wait_syscall_return[] __attribute((visibility("hidden")));

extern const char sig_wait_unmask_return[] __attribute((visibility("hidden")));

static uintptr_t sig_wait_syscall_return_pc, sig_wait_syscall_entry_pc;

/*
 * x86-64 SYSCALL leaves its return PC in RCX; the backend leaf preserves it.
 */
static __attribute((naked, noinline)) uintptr_t
sig_raw_getpid_return_addr(long (*)(long, ...)) {
  __asm__("subq $8, %rsp\n\t"
          ".cfi_adjust_cfa_offset 8\n\t"
          "movq %rdi, %r11\n\t"
          "movl $39, %edi\n\t"
          "xorl %eax, %eax\n\t"
          "call *%r11\n\t"
          "movq %rcx, %rax\n\t"
          "addq $8, %rsp\n\t"
          ".cfi_adjust_cfa_offset -8\n\t"
          "ret");
}

int sig_init_interception() {
  if (atomic_load_explicit(&sig_ready, memory_order_acquire))
    return 0;
  unsigned long _exempt = 0;
  /* Publish only a complete snapshot. Retries must not exempt our own wrappers.
   */
  for (int i = 1; i < NSIG; ++i) {
    if (i == SIGKILL || i == SIGSTOP || (i > SIGSYS && i < SIGRTMIN))
      continue;
    struct kernel_sigaction _action;
    const int _err =
        patcher_syscall_err_code(sig_raw_rt_sigaction(i, NULL, &_action));
    if (_err) {
      errno = _err;
      return -1;
    }
    if (_action.kernel_sa_handler != SIG_DFL)
      _exempt |= 1UL << (i - 1);
  }
  sig_wait_syscall_entry_pc = (uintptr_t)util_syscall_no_intercept;
  sig_wait_syscall_return_pc =
      sig_raw_getpid_return_addr(util_syscall_no_intercept);
  sig_exempt_sighand = _exempt;
  atomic_store_explicit(&sig_ready, true, memory_order_release);
  return 0;
}

/*
 * R12 holds the packet and R13 the backend leaf. The owned return slot
 * identifies a live wait without publishing a TLS pointer that siglongjmp could
 * strand. Guarded waits establish this frame before unmasking to close the
 * capture-before-entry gap without changing an application's return mask.
 */
static __attribute((naked, noinline)) long
sig_invoke_wait_syscall(struct wait_call *, long (*)(long, ...)) {
  __asm__("pushq %r12\n\t"
          ".cfi_adjust_cfa_offset 8\n\t"
          ".cfi_offset %r12, -16\n\t"
          "pushq %r13\n\t"
          ".cfi_adjust_cfa_offset 8\n\t"
          ".cfi_offset %r13, -24\n\t"
          "subq $8, %rsp\n\t"
          ".cfi_adjust_cfa_offset 8\n\t"
          "movq %rdi, %r12\n\t"
          "movq %rsi, %r13\n\t"
          "cmpq $0, (%r12)\n\t" // SYS_read
          "je 0f\n\t"
          "cmpb $0, 97(%r12)\n\t" // entry_guard
          "je 1f\n"
          "0:\n\t"
          "movl $14, %edi\n\t" // SYS_rt_sigprocmask
          "movl $2, %esi\n\t"  // SIG_SETMASK
          "leaq 88(%r12), %rdx\n\t"
          "xorl %ecx, %ecx\n\t"
          "movl $8, %r8d\n\t"
          "xorl %r9d, %r9d\n\t"
          "movq $0, (%rsp)\n\t"
          "xorl %eax, %eax\n\t"
          "call *%r13\n\t"
          ".global sig_wait_unmask_return\n\t"
          ".hidden sig_wait_unmask_return\n"
          "sig_wait_unmask_return:\n\t"
          "testq %rax, %rax\n\t"
          "js sig_wait_syscall_return\n\t"
          "movb $1, 75(%r12)\n"
          "1:\n\t"
          "movq 0(%r12), %rdi\n\t"
          "movq 8(%r12), %rsi\n\t"
          "movq 16(%r12), %rdx\n\t"
          "movq 24(%r12), %rcx\n\t"
          "movq 32(%r12), %r8\n\t"
          "movq 40(%r12), %r9\n\t"
          "movq 48(%r12), %rax\n\t"
          "movq %rax, (%rsp)\n\t"
          "xorl %eax, %eax\n\t"
          "call *%r13\n\t"
          ".global sig_wait_syscall_return\n\t"
          ".hidden sig_wait_syscall_return\n"
          "sig_wait_syscall_return:\n\t"
          "addq $8, %rsp\n\t"
          ".cfi_adjust_cfa_offset -8\n\t"
          "popq %r13\n\t"
          ".cfi_adjust_cfa_offset -8\n\t"
          ".cfi_restore %r13\n\t"
          "popq %r12\n\t"
          ".cfi_adjust_cfa_offset -8\n\t"
          ".cfi_restore %r12\n\t"
          "ret");
}

/*
 * Match only the live assembly frame, including its guarded pre-entry path.
 * Native exempt handlers do not report whether they caused a preceding EINTR.
 */
static struct wait_call *sig_interrupted_wait(const ucontext_t *ctx,
                                              bool *before_wait) {
  const greg_t *const _registers = ctx->uc_mcontext.gregs;
  *before_wait = false;
  if ((uintptr_t)_registers[REG_R13] != sig_wait_syscall_entry_pc)
    return NULL;
  const uintptr_t _pc = _registers[REG_RIP];
  struct wait_call *const _call = (void *)(uintptr_t)_registers[REG_R12];
  if (_pc >= (uintptr_t)sig_wait_unmask_return &&
      _pc < (uintptr_t)sig_wait_syscall_return) {
    if (_call->num != SYS_read && !_call->entry_guard)
      return NULL;
    *before_wait = true;
    return _call;
  }
  if (_pc < sig_wait_syscall_entry_pc || _pc > sig_wait_syscall_return_pc)
    return NULL;
  uintptr_t _return_addr;
  if (syscall_copy_user_mem(&_return_addr,
                            (const void *)(uintptr_t)_registers[REG_RSP],
                            sizeof(_return_addr)))
    return NULL;
  if (_return_addr == (uintptr_t)sig_wait_unmask_return &&
      (_call->num == SYS_read || _call->entry_guard)) {
    *before_wait = true;
    return _call;
  }
  if (_return_addr != (uintptr_t)sig_wait_syscall_return)
    return NULL;
  if ((_call->num == SYS_read || _call->entry_guard) &&
      _pc < sig_wait_syscall_return_pc - 2) {
    *before_wait = true;
    return _call;
  }
  if (_call->entry_guard && _registers[REG_RAX] == _call->num &&
      _pc == sig_wait_syscall_return_pc - 2) {
    *before_wait = true;
    return _call;
  }
  if (!(_call->num == SYS_read && _registers[REG_RAX] == SYS_read &&
        _pc == sig_wait_syscall_return_pc - 2) &&
      !(_registers[REG_RAX] == -EINTR && _pc == sig_wait_syscall_return_pc))
    return NULL;
  return _call->num != SYS_read && _call->intercepted && !_call->swallowed
             ? NULL
             : _call;
}

static __always_inline int sig_raw_sigaltstack(const stack_t *restrict ss,
                                               stack_t *restrict old_ss) {
  return util_syscall_no_intercept(SYS_sigaltstack, ss, old_ss);
}

/*
 * Caller owns a non-NULL mapping and is not executing on it. Detach the kernel
 * stack first, or keep signals blocked through thread exit.
 */
void sig_unmap_defsigstk() {
  log_verify(!patcher_syscall_err_code(
      internal_raw_munmap(sig_defsigstk, sig_enable_defsigaltstack)));

  sig_defsigstk = NULL;
}

bool sig_on_defsigstk(const void *addr) {
  return sig_defsigstk && (uintptr_t)addr >= (uintptr_t)sig_defsigstk &&
         (uintptr_t)addr - (uintptr_t)sig_defsigstk < sig_enable_defsigaltstack;
}

int sig_emulate_sigaltstack(const stack_t *restrict ss,
                            stack_t *restrict old_ss) {
  if (unlikely(sig_enable_sigaltstackeperm)) {
    return -EPERM;
  }

  /*
   * Let the kernel validate replacement/disable, then release any unused stack
   * owned by OverlaySys. Application-owned mappings are never released here.
   */
  const int _raw_ret = sig_raw_sigaltstack(ss, old_ss);
  if (unlikely(sig_defsigstk) && ss) {
    stack_t _active;
    if (!patcher_syscall_err_code(sig_raw_sigaltstack(NULL, &_active))) {
      const uintptr_t _base = (uintptr_t)sig_defsigstk;
      const uintptr_t _start = (uintptr_t)_active.ss_sp;
      const bool _overlaps =
          !(_active.ss_flags & SS_DISABLE) &&
          (_start >= _base ? _start - _base < sig_enable_defsigaltstack
                           : _base - _start < _active.ss_size);
      /*
       * SS_AUTODISARM can permit replacement while executing on the old stack.
       */
      if (!_overlaps && !sig_on_defsigstk(&_active))
        sig_unmap_defsigstk();
    }
  }

  return _raw_ret;
}

/*
 * Application-visible actions shared by supported threads, protected by the
 * action lock. Kernel actions may wrap them and filter their masks. Per-signal
 * arrays use kernel signal numbers directly; slot zero is unused.
 */
static struct kernel_sigaction sig_orig_ksa[NSIG];
/*
 * Each one-shot installation has its own identity and forwarding claim.
 * Captured identities survive reinstalls until dispatch resolves them or the
 * hook returns without dispatch. Reinstalling an identical handler still
 * creates a separate claim.
 */
enum sig_reset_state_kind {
  SIG_RESET_FREE,
  SIG_RESET_REGISTRATION,
  SIG_RESET_CAPTURE
};
struct sig_reset_state_page;
struct sig_reset_state {
  struct sig_reset_state_page *page;
  struct sig_reset_state *next, **prev;
  struct sig_reset_state *registration;
  size_t ref_cnt;
  enum sig_reset_state_kind kind;
  bool claimed, kept;
};
struct sig_reset_state_page {
  struct sig_reset_state_page *next, **prev;
  struct sig_reset_state *free;
  size_t used;
  struct sig_reset_state states[SIG_RESET_STATE_SLOTS];
};
static struct sig_reset_state_page *sig_reset_pages, *sig_reset_empty_page;
static struct sig_reset_state *sig_reset_registrations[NSIG];
static thread_local __attribute((
    tls_model("initial-exec"))) struct sig_reset_state *sig_reset_captures;

/*
 * Both registration identities and owner-held captures use stable, private
 * storage. One empty page is retained so repeated one-shot installs and
 * deliveries do not allocate a mapping for every signal.
 */
static struct sig_reset_state *
sig_alloc_reset_state(enum sig_reset_state_kind kind) {
  struct sig_reset_state_page *_page = sig_reset_pages;
  while (_page && !_page->free)
    _page = _page->next;
  if (!_page) {
    _page = internal_raw_mmap(NULL, sizeof(*_page), PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (patcher_syscall_err_code((long)_page))
      return NULL;
    _page->next = sig_reset_pages;
    _page->prev = &sig_reset_pages;
    if (_page->next)
      _page->next->prev = &_page->next;
    sig_reset_pages = _page;
    for (size_t i = 0; i < SIG_RESET_STATE_SLOTS; ++i) {
      _page->states[i].page = _page;
      _page->states[i].next = _page->free;
      _page->free = &_page->states[i];
    }
  }
  if (sig_reset_empty_page == _page)
    sig_reset_empty_page = NULL;
  struct sig_reset_state *const _state = _page->free;
  _page->free = _state->next;
  ++_page->used;
  *_state = (struct sig_reset_state){.page = _page, .ref_cnt = 1, .kind = kind};
  return _state;
}

static void sig_free_reset_state(struct sig_reset_state *state) {
  struct sig_reset_state_page *const _page = state->page;
  state->kind = SIG_RESET_FREE;
  state->ref_cnt = 0;
  state->next = _page->free;
  _page->free = state;
  if (--_page->used)
    return;
  if (!sig_reset_empty_page) {
    sig_reset_empty_page = _page;
    return;
  }
  *_page->prev = _page->next;
  if (_page->next)
    _page->next->prev = _page->prev;
  log_verify(
      !patcher_syscall_err_code(internal_raw_munmap(_page, sizeof(*_page))));
}

static void
sig_release_reset_registration(struct sig_reset_state *registration) {
  if (registration && !--registration->ref_cnt)
    sig_free_reset_state(registration);
}

/*
 * Pin the captured registration until dispatch resolution or hook cleanup.
 */
static struct sig_reset_state *sig_capture_reset_registration(int sig) {
  struct sig_reset_state *const _registration = sig_reset_registrations[sig];
  if (!_registration)
    return NULL;
  struct sig_reset_state *_capture = sig_reset_captures;
  while (_capture && _capture->registration != _registration)
    _capture = _capture->next;
  if (_capture)
    ++_capture->ref_cnt;
  else {
    _capture = sig_alloc_reset_state(SIG_RESET_CAPTURE);
    log_verify(_capture);
    _capture->registration = _registration;
    _capture->next = sig_reset_captures;
    _capture->prev = &sig_reset_captures;
    if (_capture->next)
      _capture->next->prev = &_capture->next;
    sig_reset_captures = _capture;
  }
  ++_registration->ref_cnt;
  return _capture;
}

static void sig_release_reset_capture(struct sig_reset_state *capture) {
  if (!capture)
    return;
  struct sig_reset_state *const _registration = capture->registration;
  if (!--capture->ref_cnt) {
    *capture->prev = capture->next;
    if (capture->next)
      capture->next->prev = capture->prev;
    sig_free_reset_state(capture);
  }
  sig_release_reset_registration(_registration);
}

static void sig_clear_reset_captures(void) {
  while (sig_reset_captures)
    sig_release_reset_capture(sig_reset_captures);
}

/*
 * Rebuild the private pool from installed actions and retained continuation
 * captures; discard references belonging to abandoned/sibling stacks.
 */
static void sig_reset_registration_fork(void) {
  struct sig_reset_state_page **_prev = &sig_reset_pages;
  for (struct sig_reset_state_page *_page = sig_reset_pages; _page;
       _page = _page->next) {
    _page->prev = _prev;
    _prev = &_page->next;
    for (size_t i = 0; i < SIG_RESET_STATE_SLOTS; ++i) {
      struct sig_reset_state *const _state = &_page->states[i];
      _state->page = _page;
      _state->kept = false;
      if (_state->kind == SIG_RESET_REGISTRATION)
        _state->ref_cnt = 0;
    }
  }
  for (int sig = 1; sig < NSIG; ++sig)
    if (sig_reset_registrations[sig])
      ++sig_reset_registrations[sig]->ref_cnt;
  struct sig_reset_state **_capture_prev = &sig_reset_captures;
  /*
   * CLONE_SETTLS can move the TLS head that these back-links must reference.
   */
  for (struct sig_reset_state *_capture = sig_reset_captures; _capture;
       _capture = _capture->next) {
    _capture->prev = _capture_prev;
    _capture_prev = &_capture->next;
    _capture->kept = true;
    _capture->registration->ref_cnt += _capture->ref_cnt;
  }
  sig_reset_empty_page = NULL;
  struct sig_reset_state_page *_page = sig_reset_pages;
  while (_page) {
    struct sig_reset_state_page *const _next = _page->next;
    _page->used = 0;
    _page->free = NULL;
    for (size_t i = 0; i < SIG_RESET_STATE_SLOTS; ++i) {
      struct sig_reset_state *const _state = &_page->states[i];
      if ((_state->kind == SIG_RESET_REGISTRATION && _state->ref_cnt) ||
          (_state->kind == SIG_RESET_CAPTURE && _state->kept))
        ++_page->used;
      else {
        _state->kind = SIG_RESET_FREE;
        _state->next = _page->free;
        _page->free = _state;
      }
    }
    if (!_page->used) {
      if (!sig_reset_empty_page)
        sig_reset_empty_page = _page;
      else {
        *_page->prev = _next;
        if (_next)
          _next->prev = _page->prev;
        log_verify(!patcher_syscall_err_code(
            internal_raw_munmap(_page, sizeof(*_page))));
      }
    }
    _page = _next;
  }
}

uint32_t sig_rt_sigaction_lock;

static size_t sig_blocked_threads[NSIG];

static unsigned long sig_wrapped_sighand, sig_forced_restart;

static size_t sig_deferred_cnt[NSIG];

static unsigned long sig_discard_epoch[NSIG];

unsigned long sig_deferred_seq;

/*
 * Hook completion publishes info/forward together under the action lock. Active
 * hooks and posted replay tokens pin records until completion/ACK. consumed
 * means removed by a native consumer, not rejected by a hook.
 */
struct sig_deferred_sig {
  struct sig_deferred_sig *next;
  siginfo_t info;
  kernel_sigset_t delivery_mask;
  unsigned long epoch, seq, batch;
  unsigned int cookie, active_hooks;
  int sig, forward;
  bool posted, bare, needs_hook, consumed, captured;
};

struct sig_deferred_page {
  struct sig_deferred_page *next;
  /*
   * Pool small records so realtime bursts do not require one mmap per event.
   */
  struct sig_deferred_sig sigs[16];
};

static thread_local __attribute((
    tls_model("initial-exec"))) struct sig_deferred_page *sig_deferred_pages,
    *sig_deferred_spare;

static thread_local __attribute((
    tls_model("initial-exec"))) struct sig_deferred_sig *sig_deferred_head,
    *sig_deferred_free;

static thread_local
    __attribute((tls_model("initial-exec"))) unsigned int sig_replay_serial;

static thread_local
    __attribute((tls_model("initial-exec"))) unsigned long sig_deferred_ctx;

/*
 * Private forks hold the action lock across the kernel copy. This stage also
 * supplies ownership when CLONE_SETTLS gives the child different TLS.
 */
static struct {
  void *stack;
  struct sig_call *call;
  struct sig_reset_state *captures;
  struct sig_deferred_page *pages, *spare;
  struct sigctx *saved, *retired;
  unsigned long ctx, forwarded, nonrestart;
  unsigned int serial;
} sig_staged_sig_fork;

void sig_prepare_fork(void) {
  sig_staged_sig_fork.stack = sig_defsigstk;
  sig_staged_sig_fork.call =
      atomic_load_explicit(&sig_current_sig_call, memory_order_acquire);
  sig_staged_sig_fork.captures = sig_reset_captures;
  sig_staged_sig_fork.pages = sig_deferred_pages;
  sig_staged_sig_fork.spare = sig_deferred_spare;
  sig_staged_sig_fork.saved =
      atomic_load_explicit(&sig_saved_head, memory_order_relaxed);
  sig_staged_sig_fork.retired = sig_retired_head;
  sig_staged_sig_fork.ctx = sig_deferred_ctx;
  sig_staged_sig_fork.forwarded = sig_forwarded_sigs;
  sig_staged_sig_fork.nonrestart = sig_nonrestart_sigs;
  sig_staged_sig_fork.serial = sig_replay_serial;
}

/*
 * Conservative check: unfinished/stale records also keep this true.
 */
bool sig_has_pending() { return sig_deferred_head != NULL; }

/*
 * Called with the signal/FD lock held; active hooks cannot publish readiness.
 */
unsigned long sig_pending_seq(unsigned long mask) {
  unsigned long _busy = 0, _seq = 0;
  for (const struct sig_deferred_sig *_event = sig_deferred_head; _event;
       _event = _event->next) {
    const unsigned long _bit = 1UL << (_event->sig - 1);
    if (!(mask & _bit) || (_busy & _bit) ||
        _event->epoch != sig_discard_epoch[_event->sig])
      continue;
    if (_event->active_hooks || _event->posted)
      _busy |= _bit;
    else if (_event->forward && _event->seq > _seq)
      _seq = _event->seq;
  }
  return _seq;
}

static void sig_release_deferred(struct sig_deferred_sig **link) {
  struct sig_deferred_sig *const _event = *link;
  *link = _event->next;
  --sig_deferred_cnt[_event->sig];
  _event->next = sig_deferred_free;
  sig_deferred_free = _event;
}

/*
 * Keep active/posted records pinned. Discard rejected/stale completions, then
 * coalesce accepted standard arrivals, retaining the first info/decision.
 * Native consumers have already selected distinct records; never merge them.
 */
static void sig_coalesce_deferred(int sig) {
  struct sig_deferred_sig *_first = NULL;
  struct sig_deferred_sig **_link = &sig_deferred_head;
  while (*_link) {
    struct sig_deferred_sig *const _event = *_link;
    if (_event->sig > sig)
      break;
    if (_event->sig != sig || _event->active_hooks || _event->posted) {
      _link = &_event->next;
      continue;
    }
    if (_event->epoch != sig_discard_epoch[_event->sig] || !_event->forward) {
      sig_release_deferred(_link);
      continue;
    }
    if (_event->sig < SIGRTMIN && !_event->consumed) {
      if (_first) {
        /*
         * Retain the first siginfo, but not at the cost of a later explicitly
         * captured occurrence's delivery eligibility. Its newest batch drives
         * this one coalesced delivery; an outer batch must not drive it again.
         */
        if (_event->captured &&
            (!_first->captured || _event->batch > _first->batch)) {
          _first->captured = true;
          _first->batch = _event->batch;
          _first->delivery_mask = _event->delivery_mask;
        }
        sig_release_deferred(_link);
        continue;
      }
      _first = _event;
    }
    _link = &_event->next;
  }
}

static void sig_clear_deferred(bool inherited) {
  if (!inherited)
    for (struct sig_deferred_sig *_event = sig_deferred_head; _event;
         _event = _event->next)
      --sig_deferred_cnt[_event->sig];
  while (sig_deferred_pages) {
    struct sig_deferred_page *const _page = sig_deferred_pages;
    sig_deferred_pages = _page->next;
    log_verify(
        !patcher_syscall_err_code(internal_raw_munmap(_page, sizeof(*_page))));
  }
  if (sig_deferred_spare) {
    log_verify(!patcher_syscall_err_code(
        internal_raw_munmap(sig_deferred_spare, sizeof(*sig_deferred_spare))));
    sig_deferred_spare = NULL;
  }
  sig_deferred_head = sig_deferred_free = NULL;
}

/*
 * Called only after the queue empties. Retain one spare page outside the active
 * list and discard its free-list links; allocation rebuilds them before reuse.
 */
static int sig_recycle_deferred_page(void) {
  if (!sig_deferred_pages)
    return 0;
  /* Rebuild free-list links only when the retained page is reused. */
  sig_deferred_free = NULL;
  if (sig_deferred_spare) {
    const int _err = patcher_syscall_err_code(
        internal_raw_munmap(sig_deferred_spare, sizeof(*sig_deferred_spare)));
    if (_err)
      return _err;
    sig_deferred_spare = NULL;
  }
  struct sig_deferred_page *const _page = sig_deferred_pages;
  while (_page->next) {
    struct sig_deferred_page *const _next = _page->next;
    struct sig_deferred_page *const _following = _next->next;
    const int _err =
        patcher_syscall_err_code(internal_raw_munmap(_next, sizeof(*_next)));
    if (_err)
      return _err;
    _page->next = _following;
  }
  sig_deferred_pages = NULL;
  sig_deferred_spare = _page;
  return 0;
}

/*
 * Child-only, with kernel signals blocked and the copied lock not yet acquired.
 * Discard parent pending records; only a continued stack keeps handler
 * continuations and captures.
 */
void sig_reset_fork(bool continuation) {
  sig_defsigstk = sig_staged_sig_fork.stack;
  atomic_store_explicit(&sig_current_sig_call,
                        continuation ? sig_staged_sig_fork.call : NULL,
                        memory_order_release);
  sig_reset_captures = continuation ? sig_staged_sig_fork.captures : NULL;
  sig_deferred_pages = sig_staged_sig_fork.pages;
  sig_deferred_spare = sig_staged_sig_fork.spare;
  sig_deferred_ctx = continuation ? sig_staged_sig_fork.ctx : 0;
  sig_forwarded_sigs = continuation ? sig_staged_sig_fork.forwarded : 0;
  sig_nonrestart_sigs = continuation ? sig_staged_sig_fork.nonrestart : 0;
  sig_replay_serial = continuation ? sig_staged_sig_fork.serial : 0;
  sig_reset_registration_fork();
  sig_rt_sigaction_lock = 0;
  __builtin_memset(sig_blocked_threads, 0, sizeof(sig_blocked_threads));
  sig_logical_sigmask_inited = false;
  __builtin_memset(sig_deferred_cnt, 0, sizeof(sig_deferred_cnt));
  sig_clear_deferred(true);
  atomic_store_explicit(&sig_saved_head, sig_staged_sig_fork.saved,
                        memory_order_relaxed);
  sig_retired_head = sig_staged_sig_fork.retired;
  sig_clear_captured();
  ++sig_deferred_ctx;
}

/*
 * CLONE_SETTLS may point at a copied TCB. Its resource pointers still belong to
 * the donor thread in the shared address space; detach without releasing them.
 */
void sig_reset_thread() {
  sig_defsigstk = NULL;
  atomic_store_explicit(&sig_current_sig_call, NULL, memory_order_release);
  sig_reset_captures = NULL;
  sig_deferred_pages = NULL;
  sig_deferred_spare = NULL;
  sig_deferred_head = sig_deferred_free = NULL;
  atomic_store_explicit(&sig_saved_head, NULL, memory_order_relaxed);
  sig_retired_head = NULL;
  sig_logical_sigmask = (kernel_sigset_t){0};
  sig_logical_sigmask_inited = false;
  sig_suppressed_sigmask = 0;
  sig_deferred_ctx = 0;
  sig_replay_serial = 0;
  sig_forwarded_sigs = sig_nonrestart_sigs = 0;
}

/*
 * Reserve before entering the hook, so nested arrivals retain FIFO order.
 */
static struct sig_deferred_sig *
sig_remember_deferred(int sig, const siginfo_t *info, bool consumed) {
  struct sig_deferred_sig **_link = &sig_deferred_head;
  while (*_link && ((*_link)->sig < sig || (!consumed && (*_link)->sig == sig)))
    _link = &(*_link)->next;
  if (!sig_deferred_free) {
    struct sig_deferred_page *const _page =
        sig_deferred_spare
            ? sig_deferred_spare
            : internal_raw_mmap(NULL, sizeof(*_page), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    sig_deferred_spare = NULL;
    const int _err = patcher_syscall_err_code((long)_page);
    if (_err) {
      errno = _err;
      return NULL;
    }
    _page->next = sig_deferred_pages;
    sig_deferred_pages = _page;
    for (size_t i = 0; i < sizeof(_page->sigs) / sizeof(_page->sigs[0]); ++i) {
      _page->sigs[i].next = sig_deferred_free;
      sig_deferred_free = &_page->sigs[i];
    }
  }
  struct sig_deferred_sig *const _event = sig_deferred_free;
  sig_deferred_free = _event->next;
  *_event = (struct sig_deferred_sig){.next = *_link,
                                      .info = *info,
                                      .epoch = sig_discard_epoch[sig],
                                      .seq = ++sig_deferred_seq,
                                      .active_hooks = 1,
                                      .consumed = consumed,
                                      .sig = sig};
  /*
   * A native consumer has already removed this occurrence from the kernel. Keep
   * it distinct from later standard arrivals and ahead of later RT data.
   */
  if (consumed && *_link && (*_link)->sig == sig)
    _event->seq = (*_link)->seq;
  *_link = _event;
  ++sig_deferred_cnt[sig];
  return _event;
}

/*
 * The caller has established the full physical mask before taking the mutex.
 */
static void sig_lock_action(int saved_errno) {
  atomic_store_explicit(&syscall_internal_emulation, true,
                        memory_order_relaxed);
  log_verify_err(usersched_lock_pi2(
      &sig_rt_sigaction_lock, _overlaysys_syscall_self_tid,
      USERSCHED_LOCK_RESTART | USERSCHED_LOCK_NOEAGAIN | FUTEX_PRIVATE_FLAG,
      100 * usersched_tsc_1us, NULL));
  errno = saved_errno;
}

void sig_lock_rt_sigaction(kernel_sigset_t *oldmask) {
  const int _errno = errno;
  /*
   * Internal critical sections must bypass application mask filtering.
   */
  log_verify(!patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, oldmask)));
  sig_lock_action(_errno);
}

/*
 * Default forwarding may have unblocked a signal under the lock, so it must
 * force restoration even when oldmask requests the full physical mask.
 */
static void sig_unlock_action(const kernel_sigset_t *oldmask,
                              bool force_restore) {
  const int _errno = errno;
  log_verify_err(usersched_unlock_pi(&sig_rt_sigaction_lock,
                                     _overlaysys_syscall_self_tid,
                                     FUTEX_PRIVATE_FLAG));
  atomic_store_explicit(&syscall_internal_emulation, false,
                        memory_order_relaxed);
  const unsigned long _unblockable =
      (1UL << (SIGKILL - 1)) | (1UL << (SIGSTOP - 1));
  if (force_restore || (oldmask->__val[0] | _unblockable) != UINT64_MAX)
    log_verify(!patcher_syscall_err_code(
        sig_raw_rt_sigprocmask(SIG_SETMASK, oldmask, NULL)));
  errno = _errno;
}

void sig_unlock_rt_sigaction(const kernel_sigset_t *oldmask) {
  /*
   * Ordinary critical sections retain the full physical mask. Restoring that
   * same mask can therefore be skipped.
   */
  sig_unlock_action(oldmask, false);
}

/*
 * For inhibited signals, force shared SA_RESTART while the action is SIG_IGN or
 * any participating thread blocks. changed_mask selects masks to refilter.
 */
/* Action installation references the wrapper, whose forwarding path updates
 * those same actions. This cycle requires a declaration before installation. */
static void sig_sighand_wrapper(int, siginfo_t *, void *);

static int sig_refresh_wrapped_sigactions_res(unsigned long changed_mask) {
  const unsigned long _inhibit =
      atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed);
  for (unsigned long _remaining = sig_wrapped_sighand; _remaining;
       _remaining &= _remaining - 1) {
    const int i = __builtin_ctzl(_remaining) + 1;
    const unsigned long _bit = 1UL << (i - 1);
    const bool _special = sig_orig_ksa[i].kernel_sa_handler == SIG_DFL ||
                          sig_orig_ksa[i].kernel_sa_handler == SIG_IGN;
    const bool _keep =
        !_special || sig_deferred_cnt[i] ||
        (sig_orig_ksa[i].kernel_sa_handler == SIG_DFL
             ? (atomic_load_explicit(&sig_force_sighand, memory_order_relaxed) &
                _bit)
             : (_inhibit & _bit));
    if (!_keep) {
      const int _err = patcher_syscall_err_code(
          sig_raw_rt_sigaction(i, &sig_orig_ksa[i], NULL));
      if (_err)
        return _err;
      sig_wrapped_sighand &= ~_bit;
      sig_forced_restart &= ~_bit;
      continue;
    }
    const bool _force = (_inhibit & _bit) &&
                        !(sig_orig_ksa[i].sa_flags & SA_RESTART) &&
                        (sig_orig_ksa[i].kernel_sa_handler == SIG_IGN ||
                         sig_blocked_threads[i]);
    const bool _refresh_mask = sig_orig_ksa[i].sa_mask.__val[0] & changed_mask;
    if (_force == !!(sig_forced_restart & _bit) && !_refresh_mask)
      continue;
    struct kernel_sigaction _ksa;
    int _err = patcher_syscall_err_code(sig_raw_rt_sigaction(i, NULL, &_ksa));
    if (_err)
      return _err;
    if (_ksa.kernel_sa_sigaction != sig_sighand_wrapper) {
      sig_wrapped_sighand &= ~_bit;
      sig_forced_restart &= ~_bit;
      continue;
    }
    _ksa.sa_flags = (_ksa.sa_flags & ~SA_RESTART) |
                    (sig_orig_ksa[i].sa_flags & SA_RESTART) |
                    (_force ? SA_RESTART : 0);
    if (_refresh_mask)
      _ksa.sa_mask.__val[0] = sig_orig_ksa[i].sa_mask.__val[0] & ~_inhibit;
    _err = patcher_syscall_err_code(sig_raw_rt_sigaction(i, &_ksa, NULL));
    if (_err)
      return _err;
    if (_force)
      sig_forced_restart |= _bit;
    else
      sig_forced_restart &= ~_bit;
  }
  return 0;
}

void sig_refresh_wrapped_sigactions(unsigned long changed_mask) {
  log_verify(!sig_refresh_wrapped_sigactions_res(changed_mask));
}

/*
 * Called with rt_sigaction_lock held and local signals blocked.
 */
static int sig_set_logical_sigmask_res(kernel_sigset_t mask) {
  mask.__val[0] &= ~((1UL << (SIGKILL - 1)) | (1UL << (SIGSTOP - 1)));
  const unsigned long _old =
      sig_logical_sigmask_inited ? sig_logical_sigmask.__val[0] : 0;
  const unsigned long _changed = _old ^ mask.__val[0];
  for (unsigned long _remaining = _changed; _remaining;
       _remaining &= _remaining - 1) {
    const int i = __builtin_ctzl(_remaining) + 1;
    const unsigned long _bit = 1UL << (i - 1);
    if (mask.__val[0] & _bit)
      ++sig_blocked_threads[i];
    else
      --sig_blocked_threads[i];
  }
  sig_logical_sigmask = mask;
  sig_logical_sigmask_inited = true;
  return _changed ? sig_refresh_wrapped_sigactions_res(0) : 0;
}

void sig_set_logical_sigmask(kernel_sigset_t mask) {
  log_verify(!sig_set_logical_sigmask_res(mask));
}

void sig_exit_sig_state() {
  sig_clear_reset_captures();
  sig_clear_deferred(false);
  sig_clear_captured();
  if (sig_logical_sigmask_inited)
    sig_set_logical_sigmask((kernel_sigset_t){0});
  sig_refresh_wrapped_sigactions(0);
}

/*
 * Preserve bits hidden by our last filter while accepting other kernel changes.
 */
void sig_sync_logical_sigmask(kernel_sigset_t actual) {
  if (sig_logical_sigmask_inited)
    actual.__val[0] |= sig_logical_sigmask.__val[0] & sig_suppressed_sigmask;
  sig_set_logical_sigmask(actual);
}

/*
 * Under the action lock, compute the kernel mask and remember removed bits. The
 * caller installs the result; this function does not change the kernel.
 */
kernel_sigset_t sig_filter_logical_sigmask() {
  sig_suppressed_sigmask =
      sig_logical_sigmask.__val[0] &
      atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed);
  kernel_sigset_t _mask = sig_logical_sigmask;
  _mask.__val[0] &= ~sig_suppressed_sigmask;
  return _mask;
}

static struct kernel_sigaction
sig_wrap_sigaction(int signum, const struct kernel_sigaction *kact) {
  struct kernel_sigaction _ksa = *kact;
  const unsigned long _bit = 1UL << (signum - 1);
  if (sig_exempt_sighand & _bit)
    return _ksa;
  const unsigned long _inhibit =
      atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed);
  const bool _force =
      atomic_load_explicit(&sig_force_sighand, memory_order_relaxed) & _bit;
  const bool _wrap = sig_deferred_cnt[signum] ||
                     (kact->kernel_sa_handler == SIG_DFL   ? _force
                      : kact->kernel_sa_handler == SIG_IGN ? !!(_inhibit & _bit)
                                                           : true);
  _ksa.sa_mask.__val[0] &= ~_inhibit;
  if (_wrap) {
    _ksa.kernel_sa_sigaction = sig_sighand_wrapper;
    /*
     * Actions are shared: a caller without a stack must not disable other
     * threads' default stacks. The kernel falls back if this thread has none.
     */
    _ksa.sa_flags |= SA_SIGINFO | (sig_enable_defsigaltstack ? SA_ONSTACK : 0);
    /*
     * Reserve the delivery before allowing another instance. Kernel NODEFER can
     * otherwise stack an entire RT burst before our first instruction.
     */
    _ksa.sa_flags &= ~SA_NODEFER;
    if (_inhibit & _bit) {
      if (kact->kernel_sa_handler == SIG_IGN || sig_blocked_threads[signum])
        _ksa.sa_flags |= SA_RESTART;
    }
    /*
     * Resolve one-shot state when the continuation dispatches. Hook entry alone
     * must not consume the registration, whether forwarding is manual or
     * automatic.
     */
    _ksa.sa_flags &= ~SA_RESETHAND;
    /*
     * Replacing SIG_IGN must retain its kernel no-zombie behavior.
     */
    if (signum == SIGCHLD && kact->kernel_sa_handler == SIG_IGN)
      _ksa.sa_flags |= SA_NOCLDWAIT;
  }
  return _ksa;
}

static int sig_normalize_sigaction(int signum,
                                   struct kernel_sigaction *action) {
  action->sa_mask.__val[0] &=
      ~((1UL << (SIGKILL - 1)) | (1UL << (SIGSTOP - 1)));
  /*
   * These long-standing x86 flags need no feature-probe syscall. 0x04000000 is
   * SA_RESTORER, which GLIBC does not expose in its public signal header.
   */
  const unsigned long _known = SA_NOCLDSTOP | SA_NOCLDWAIT | SA_SIGINFO |
                               SA_ONSTACK | SA_RESTART | SA_NODEFER |
                               SA_RESETHAND | 0x04000000UL;
  if (action->sa_flags & ~_known) {
    struct kernel_sigaction _accepted;
    const int _err = patcher_syscall_err_code(
        sig_raw_rt_sigaction(signum, NULL, &_accepted));
    if (_err)
      return _err;
    action->sa_flags &= _accepted.sa_flags | SA_SIGINFO | SA_ONSTACK |
                        SA_NODEFER | SA_RESETHAND | SA_RESTART | SA_NOCLDWAIT;
  }
  return 0;
}

/*
 * Record a successfully installed action while the action lock is held.
 */
static int sig_record_sigaction_res(int sig,
                                    const struct kernel_sigaction *action) {
  const int _err = sig_normalize_sigaction(sig, &sig_orig_ksa[sig]);
  const unsigned long _bit = 1UL << (sig - 1);
  if (action->kernel_sa_sigaction == sig_sighand_wrapper)
    sig_wrapped_sighand |= _bit;
  else
    sig_wrapped_sighand &= ~_bit;
  /* Temporary masks need the wait frame when an original handler can run. */
  const bool _handler = sig_orig_ksa[sig].kernel_sa_handler != SIG_DFL &&
                        sig_orig_ksa[sig].kernel_sa_handler != SIG_IGN;
  if (action->kernel_sa_sigaction == sig_sighand_wrapper &&
      (_handler || (sig != SIGSEGV && sig != SIGBUS)))
    atomic_fetch_or_explicit(&sig_wait_sighand, _bit, memory_order_release);
  else
    atomic_fetch_and_explicit(&sig_wait_sighand, ~_bit, memory_order_release);
  if ((action->sa_flags & SA_RESTART) &&
      !(sig_orig_ksa[sig].sa_flags & SA_RESTART))
    sig_forced_restart |= _bit;
  else
    sig_forced_restart &= ~_bit;
  return _err;
}

static void sig_record_sigaction(int sig,
                                 const struct kernel_sigaction *action) {
  log_verify(!sig_record_sigaction_res(sig, action));
}

/*
 * Only self-directed, nonnegative si_code values can carry this private marker.
 */
static bool sig_replay_marker(const siginfo_t *info) {
  return (info->si_code == SI_KERNEL || info->si_code == SI_USER) &&
         ((unsigned int)info->si_errno & 0xff000000U) == 0x4f000000U;
}

/*
 * Match a private replay frame, or reserve an arriving signal before its hook.
 * Called under the action lock with real signals blocked.
 */
static struct sig_deferred_sig *
sig_begin_deferred_delivery(int sig, siginfo_t *info, bool blocked,
                            bool *replay, int *forward) {
  *replay = sig_replay_marker(info);
  bool _backlog = false;
  struct sig_deferred_sig **_link = &sig_deferred_head;
  while (*_link) {
    struct sig_deferred_sig *const _event = *_link;
    if (_event->sig != sig) {
      _link = &_event->next;
      continue;
    }
    const bool _bare = _event->posted && _event->bare &&
                       info->si_code == SI_USER && info->si_errno == 0 &&
                       info->si_pid == 0 && info->si_uid == 0;
    if (_event->posted &&
        ((*replay && (unsigned int)info->si_errno == _event->cookie) ||
         _bare)) {
      _event->posted = false;
      *replay = true;
      *forward = 0;
      if (_event->needs_hook) {
        _event->needs_hook = false;
        *info = _event->info;
        *replay = false;
        *forward = 1;
        return _event;
      } else if (_event->epoch != sig_discard_epoch[sig])
        sig_release_deferred(_link);
      else if (!blocked && !_event->active_hooks) {
        *info = _event->info;
        *forward = _event->forward;
        sig_release_deferred(_link);
      }
      /*
       * A blocked replay may now merge with arrivals accepted while its token
       * was still posted. Active hooks retain their own records.
       */
      sig_coalesce_deferred(sig);
      return NULL;
    }
    if (!*replay && _event->posted && sig < SIGRTMIN)
      _event->posted = false;
    _backlog |= !_event->consumed && _event->epoch == sig_discard_epoch[sig];
    _link = &_event->next;
  }
  if (*replay) {
    *forward = 0;
    return NULL;
  }
  if (!blocked && !_backlog)
    return NULL;
  struct sig_deferred_sig *const _event =
      sig_remember_deferred(sig, info, false);
  log_verify(_event);
  return _event;
}

static int sig_post_deferred_sig(struct sig_deferred_sig *event) {
  event->cookie = 0x4f000000U | (++sig_replay_serial & 0x00ffffffU);
  siginfo_t _token = {.si_signo = event->sig,
                      .si_errno = (int)event->cookie,
                      .si_code = SI_KERNEL};
  const pid_t _pid = _overlaysys_syscall_self_pid > 0
                         ? _overlaysys_syscall_self_pid
                         : internal_raw_getpid();
  int _res = sig_raw_rt_tgsigqueueinfo(_pid, _overlaysys_syscall_self_tid,
                                       event->sig, &_token);
  event->bare = event->sig < SIGRTMIN;
  if (_res == -EAGAIN) {
    /*
     * SI_USER can post a signal bit even when the siginfo quota is full.
     */
    _token.si_code = SI_USER;
    event->bare = true;
    _res = sig_raw_rt_tgsigqueueinfo(_pid, _overlaysys_syscall_self_tid,
                                     event->sig, &_token);
  }
  event->posted = !_res;
  return _res;
}

static int sig_prepare_deferred_replay_res(unsigned long *ready,
                                           int *postponed) {
  *ready = 0;
  *postponed = 0;
  if (syscall_clone_sigmask_pending)
    return 0;
  if (!sig_deferred_head) {
    /*
     * The first empty-queue visit refreshes removed records' shared actions.
     * Once the pages have been recycled, later empty visits need no refresh.
     */
    if (sig_deferred_pages) {
      const int _err = sig_refresh_wrapped_sigactions_res(0);
      if (_err)
        return _err;
      return sig_recycle_deferred_page();
    }
    return 0;
  }
  kernel_sigset_t _kernel_pending;
  int _err = patcher_syscall_err_code(sig_raw_rt_sigpending(&_kernel_pending));
  if (_err)
    return _err;
  unsigned long _seen = 0, _ready = 0;
  struct sig_deferred_sig **_link = &sig_deferred_head;
  while (*_link) {
    struct sig_deferred_sig *const _event = *_link;
    const int _sig = _event->sig;
    const unsigned long _bit = 1UL << (_sig - 1);
    const bool _stale = _event->epoch != sig_discard_epoch[_sig];
    if (_stale && !_event->active_hooks && !_event->posted) {
      sig_release_deferred(_link);
      continue;
    }
    if ((_seen & _bit) || _event->active_hooks) {
      _seen |= _bit;
      _link = &_event->next;
      continue;
    }
    _seen |= _bit;
    if (sig_logical_sigmask.__val[0] & _bit) {
      _link = &_event->next;
      continue;
    }
    if (!_event->posted &&
        (_stale || !_event->forward ||
         sig_orig_ksa[_sig].kernel_sa_handler == SIG_IGN ||
         (sig_orig_ksa[_sig].kernel_sa_handler == SIG_DFL &&
          (sig_sigdef(_sig) == sig_Ign || sig_sigdef(_sig) == sig_Cont)))) {
      sig_release_deferred(_link);
      _seen &= ~_bit;
      continue;
    }
    _ready |= _bit;
    if (!_event->posted && !(_kernel_pending.__val[0] & _bit)) {
      const int _res = sig_post_deferred_sig(_event);
      if (_res)
        *postponed = patcher_syscall_err_code(_res);
    }
    /*
     * Dispatch one at a time: its handler may reblock other pending signals.
     * Keep the record until the frame acknowledges it; a successful standard
     * send can coalesce with a concurrently arriving signal.
     */
    break;
  }
  *ready = _ready;
  _err = sig_refresh_wrapped_sigactions_res(0);
  if (_err)
    return _err;
  return !sig_deferred_head ? sig_recycle_deferred_page() : 0;
}

static unsigned long sig_prepare_deferred_replay() {
  unsigned long _ready;
  int _postponed;
  log_verify(!sig_prepare_deferred_replay_res(&_ready, &_postponed));
  if (_postponed)
    log_msg(LOG_DEBUG, "deferred signal replay postponed (%d)", _postponed);
  return _ready;
}

void sig_unlock_with_replay(kernel_sigset_t mask, bool sigreturn) {
  const unsigned long _ready = sig_prepare_deferred_replay();
  if (sigreturn)
    mask.__val[0] |=
        _ready; // Replay only after the application context is restored.
  sig_unlock_rt_sigaction(&mask);
}

int sig_emulate_rt_sigaction(int signum,
                             const struct kernel_sigaction *restrict kact,
                             struct kernel_sigaction *restrict oldkact,
                             size_t sigsetsize) {
  if (sigsetsize != sizeof(kernel_sigset_t))
    return -EINVAL;
  if (signum <= 0 || signum >= NSIG)
    return sig_raw_rt_sigaction(signum, kact, oldkact);
  if (sig_exempt_sighand & (1UL << (signum - 1)))
    return sig_raw_rt_sigaction(signum, kact, oldkact);

  struct kernel_sigaction _input;
  if (kact) {
    const int _err = syscall_copy_user_mem(&_input, kact, sizeof(_input));
    if (_err)
      return _err;
    kact = &_input;
  }

  kernel_sigset_t _oldmask;
  sig_lock_rt_sigaction(&_oldmask);
  sig_sync_logical_sigmask(_oldmask);

  const struct kernel_sigaction _orig_ksa = sig_orig_ksa[signum];
  struct sig_reset_state *_new_registration = NULL;
  if (kact && (kact->sa_flags & SA_RESETHAND) &&
      kact->kernel_sa_handler != SIG_DFL &&
      kact->kernel_sa_handler != SIG_IGN) {
    _new_registration = sig_alloc_reset_state(SIG_RESET_REGISTRATION);
    if (!_new_registration) {
      sig_unlock_with_replay(_oldmask, false);
      return -ENOMEM;
    }
  }
  struct kernel_sigaction _ksa;
  if (kact) {
    _ksa = sig_wrap_sigaction(signum, kact);
    /*
     * Publish the original before another thread can enter the new wrapper.
     */
    sig_orig_ksa[signum] = *kact;
  }

  struct kernel_sigaction _old;
  int _raw_ret =
      sig_raw_rt_sigaction(signum, kact ? &_ksa : NULL, oldkact ? &_old : NULL);
  if (likely(!patcher_syscall_err_code(_raw_ret))) {
    if (oldkact && _old.kernel_sa_sigaction == sig_sighand_wrapper)
      _old = _orig_ksa;
    if (kact) {
      struct sig_reset_state *const _prev = sig_reset_registrations[signum];
      sig_reset_registrations[signum] = _new_registration;
      _new_registration = NULL;
      sig_release_reset_registration(_prev);
      sig_record_sigaction(signum, &_ksa);
      if (kact->kernel_sa_handler == SIG_IGN ||
          (kact->kernel_sa_handler == SIG_DFL && sig_sigdef(signum) == sig_Ign))
        ++sig_discard_epoch[signum];
    }
    /*
     * Kernel installation precedes copy-out; EFAULT must not undo the action.
     */
    if (oldkact)
      _raw_ret = syscall_copy_user_mem(oldkact, &_old, sizeof(_old));
  } else if (kact)
    sig_orig_ksa[signum] = _orig_ksa;

  sig_release_reset_registration(_new_registration);

  sig_unlock_with_replay(_oldmask, false);

  return _raw_ret;
}

int sig_emulate_rt_sigprocmask(int how, const kernel_sigset_t *restrict set,
                               kernel_sigset_t *restrict oldset,
                               size_t sigsetsize) {
  if (sigsetsize != sizeof(kernel_sigset_t))
    return -EINVAL;
  if (set && how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK)
    return sig_raw_rt_sigprocmask(how, set, oldset);

  kernel_sigset_t _set;
  if (set) {
    const int _err = syscall_copy_user_mem(&_set, set, sizeof(_set));
    if (_err)
      return _err;
  }

  kernel_sigset_t _actual;
  sig_lock_rt_sigaction(&_actual);
  sig_sync_logical_sigmask(_actual);
  const kernel_sigset_t _old = sig_logical_sigmask;
  if (set) {
    if (how == SIG_BLOCK)
      _set.__val[0] |= _old.__val[0];
    else if (how == SIG_UNBLOCK)
      _set.__val[0] = _old.__val[0] & ~_set.__val[0];
    sig_set_logical_sigmask(_set);
    _actual = sig_filter_logical_sigmask();
  }
  const int _err =
      oldset ? syscall_copy_user_mem(oldset, &_old, sizeof(_old)) : 0;
  sig_unlock_with_replay(_actual, false);
  return _err;
}

int sig_emulate_rt_sigpending(kernel_sigset_t *set, size_t sigsetsize) {
  if (sigsetsize > sizeof(kernel_sigset_t))
    return -EINVAL;
  if (!sigsetsize)
    return 0;
  kernel_sigset_t _actual, _pending;
  sig_lock_rt_sigaction(&_actual);
  sig_sync_logical_sigmask(_actual);
  int _res = sig_raw_rt_sigpending(&_pending);
  if (!_res) {
    /*
     * Software readiness cannot pass an unfinished delivery of the same signal.
     */
    unsigned long _busy = 0;
    for (const struct sig_deferred_sig *_event = sig_deferred_head; _event;
         _event = _event->next) {
      if (_event->epoch != sig_discard_epoch[_event->sig])
        continue;
      const unsigned long _bit = 1UL << (_event->sig - 1);
      if (_event->active_hooks || _event->posted)
        _busy |= _bit;
      else if (!(_busy & _bit) && _event->forward)
        _pending.__val[0] |= _bit;
    }
    _pending.__val[0] &= sig_logical_sigmask.__val[0];
    _res = syscall_copy_user_mem(set, &_pending, sigsetsize);
  }
  sig_unlock_rt_sigaction(&_actual);
  return _res;
}

thread_local
    __attribute((tls_model("initial-exec"))) unsigned long sig_forwarded_sigs,
    sig_nonrestart_sigs;

static struct sig_deferred_sig **
sig_find_signalfd_event_locked(unsigned long mask) {
  struct sig_deferred_sig **_link = &sig_deferred_head;
  unsigned long _seen = 0;
  while (*_link) {
    struct sig_deferred_sig *const _event = *_link;
    const unsigned long _bit = 1UL << (_event->sig - 1);
    if ((_seen & _bit) || !(mask & _bit) ||
        _event->epoch != sig_discard_epoch[_event->sig]) {
      _link = &_event->next;
      continue;
    }
    /*
     * An incomplete hook retains its place in realtime FIFO order.
     */
    if (_event->active_hooks || _event->posted)
      _seen |= _bit;
    else if (_event->forward)
      return _link;
    _link = &_event->next;
  }
  return NULL;
}

static long sig_raw_rt_sigsuspend(struct wait_call *call) {
  call->num = SYS_rt_sigsuspend;
  return sig_invoke_wait_syscall(call, util_syscall_no_intercept);
}

long sig_raw_ppoll(struct wait_call *call) {
  call->num = SYS_ppoll;
  return sig_invoke_wait_syscall(call, util_syscall_no_intercept);
}

long sig_raw_pselect6(struct wait_call *call) {
  call->num = SYS_pselect6;
  return sig_invoke_wait_syscall(call, util_syscall_no_intercept);
}

static long sig_raw_epoll_pwait(struct wait_call *call) {
  call->num = SYS_epoll_pwait;
  return sig_invoke_wait_syscall(call, util_syscall_no_intercept);
}

static long sig_raw_epoll_pwait2(struct wait_call *call) {
  call->num = SYS_epoll_pwait2;
  return sig_invoke_wait_syscall(call, util_syscall_no_intercept);
}

static long sig_raw_rt_sigtimedwait(struct wait_call *call) {
  call->num = SYS_rt_sigtimedwait;
  return sig_invoke_wait_syscall(call, util_syscall_no_intercept);
}

long sig_raw_read_wait(struct wait_call *call) {
  call->num = SYS_read;
  return sig_invoke_wait_syscall(call, util_syscall_no_intercept);
}

/*
 * Enter and return with the action lock held, releasing it around the wait.
 * Stage the complete original mask so native exempt handlers see its return
 * context; the kernel wait atomically installs the filtered temporary mask.
 * Reconcile handler edits on return. Only the live assembly frame identifies a
 * signal received during this temporary-mask interval.
 */
long sig_run_masked_wait(struct wait_call *call) {
  if (!call->saved_dispatch && sig_has_captured())
    return -EINTR;
  sig_set_logical_sigmask(call->temporary);
  kernel_sigset_t _temporary = sig_filter_logical_sigmask();
  sig_prepare_deferred_replay();
  sig_set_logical_sigmask(call->orig);
  sig_filter_logical_sigmask();
  call->intercepted = call->swallowed = false;
  /*
   * The assembly frame restores the original mask before kernel entry. A
   * capture in that guarded interval redirects it to EINTR instead of sleep;
   * native handlers still see the application's original return mask.
   */
  call->entry_mask = call->orig;
  call->entry_guard = true;
  sig_unlock_rt_sigaction(&sig_fset);
  long _res;
  switch (call->num) {
  case SYS_rt_sigsuspend:
    call->args[0] = (long)&_temporary;
    call->args[1] = sizeof(_temporary);
    _res = sig_raw_rt_sigsuspend(call);
    break;
  case SYS_ppoll:
    call->args[3] = (long)&_temporary;
    call->args[4] = sizeof(_temporary);
    _res = sig_raw_ppoll(call);
    break;
  case SYS_pselect6: {
    const struct {
      const kernel_sigset_t *set;
      size_t size;
    } _arg = {&_temporary, sizeof(_temporary)};
    call->args[5] = (long)&_arg;
    _res = sig_raw_pselect6(call);
    break;
  }
  case SYS_epoll_pwait:
    call->args[4] = (long)&_temporary;
    call->args[5] = sizeof(_temporary);
    _res = sig_raw_epoll_pwait(call);
    break;
  default:
    call->args[4] = (long)&_temporary;
    call->args[5] = sizeof(_temporary);
    _res = sig_raw_epoll_pwait2(call);
    break;
  }
  kernel_sigset_t _actual;
  sig_lock_rt_sigaction(&_actual);
  if (call->intercepted) {
    if (call->swallowed)
      sig_set_logical_sigmask(call->orig);
    else
      sig_sync_logical_sigmask(_actual);
  } else
    sig_set_logical_sigmask(_actual);
  call->orig = sig_logical_sigmask;
  return _res;
}

/*
 * Called under the action lock after a native consumer removed an occurrence.
 * Repost wrapped, inhibited arrivals through a real hook frame before exposing
 * them to the consumer.
 */
int sig_proc_native_sig(int sig, siginfo_t *info) {
  if ((atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed) &
       sig_wrapped_sighand & (1UL << (sig - 1))) &&
      !sig_replay_marker(info)) {
    struct sig_deferred_sig *const _event =
        sig_remember_deferred(sig, info, true);
    if (!_event)
      return -errno;
    _event->needs_hook = true;
    const int _posted = sig_post_deferred_sig(_event);
    if (_posted) {
      _event->needs_hook = false;
      --_event->active_hooks;
      return _posted;
    }
    /*
     * Deliver a fresh kernel frame with the saved logical mask. Automatic
     * forwarding stays deferred; manual continuation and context edits remain
     * available to the hook.
     */
    sig_unlock_rt_sigaction(&(kernel_sigset_t){
        .__val = {sig_logical_sigmask.__val[0] &
                  ~atomic_load_explicit(&sig_inhibit_sigblock,
                                        memory_order_relaxed)}});
    kernel_sigset_t _actual;
    sig_lock_rt_sigaction(&_actual);
    sig_sync_logical_sigmask(_actual);
    return -EINPROGRESS;
  }
  if (sig_replay_marker(info)) {
    bool _replay;
    int _forward = 1;
    sig_begin_deferred_delivery(sig, info, false, &_replay, &_forward);
    return _forward ? sig : -EINPROGRESS;
  }
  return sig;
}

/*
 * Under the action lock, consume the lowest eligible signal across both stores.
 * Return its number, zero if none, or a negative error. -EINPROGRESS asks the
 * caller to retry after hook/replay-marker handling changed the queue.
 */
int sig_take_pending_sig(unsigned long mask, siginfo_t *info) {
  struct sig_deferred_sig **_link = &sig_deferred_head;
  while (*_link) {
    struct sig_deferred_sig *_event = *_link;
    if ((mask & (1UL << (_event->sig - 1))) && !_event->posted &&
        !_event->active_hooks &&
        (_event->epoch != sig_discard_epoch[_event->sig] || !_event->forward))
      sig_release_deferred(_link);
    else
      _link = &_event->next;
  }
  _link = sig_find_signalfd_event_locked(mask);
  kernel_sigset_t _native;
  int _res = sig_raw_rt_sigpending(&_native);
  if (_res)
    return _res;
  _native.__val[0] &= mask;
  const int _native_sig =
      _native.__val[0] ? __builtin_ctzl(_native.__val[0]) + 1 : NSIG;
  if (_link && (*_link)->sig <= _native_sig) {
    *info = (*_link)->info;
    _res = (*_link)->sig;
    sig_release_deferred(_link);
    syscall_refresh_fd_edges_locked();
    return _res;
  }
  if (!_native.__val[0])
    return 0;
  _native.__val[0] = 1UL << (_native_sig - 1);
  const struct timespec _zero = {0};
  struct wait_call _call = {
      .args = {(long)&_native, (long)info, (long)&_zero, sizeof(_native)}};
  _res = sig_raw_rt_sigtimedwait(&_call);
  if (_res == -EAGAIN)
    return 0;
  if (_res <= 0)
    return _res;
  return sig_proc_native_sig(_res, info);
}

long sig_emulate_rt_sigtimedwait(const kernel_sigset_t *set, siginfo_t *info,
                                 const struct timespec *timeout, size_t size) {
  if (size != sizeof(kernel_sigset_t))
    return -EINVAL;
  kernel_sigset_t _set;
  int _res = syscall_copy_user_mem(&_set, set, sizeof(_set));
  if (_res)
    return _res;
  _set.__val[0] &= ~((1UL << (SIGKILL - 1)) | (1UL << (SIGSTOP - 1)));
  struct timespec _remaining = {0}, _deadline = {0};
  if (timeout) {
    _res = syscall_copy_user_mem(&_remaining, timeout, sizeof(_remaining));
    if (_res)
      return _res;
    if (_remaining.tv_sec < 0 || _remaining.tv_nsec < 0 ||
        _remaining.tv_nsec >= 1000000000)
      return -EINVAL;
    _deadline = syscall_wait_deadline(_remaining);
  }
  kernel_sigset_t _actual;
  sig_lock_rt_sigaction(&_actual);
  sig_sync_logical_sigmask(_actual);
  const unsigned long _forwarded = sig_forwarded_sigs;
  for (;;) {
    if (sig_has_captured()) {
      _res = -EINTR;
      break;
    }
    siginfo_t _info = {0};
    _res = sig_take_pending_sig(_set.__val[0], &_info);
    if (_res == -EINPROGRESS)
      continue;
    if (_res) {
      if (_res > 0 && info) {
        const int _err = syscall_copy_user_mem(info, &_info, sizeof(_info));
        if (_err)
          _res = _err;
      }
      break;
    }
    if (timeout) {
      _remaining = syscall_wait_remaining(_deadline);
      if (!_remaining.tv_sec && !_remaining.tv_nsec) {
        _res = -EAGAIN;
        break;
      }
    }
    struct wait_call _call = {.num = SYS_rt_sigtimedwait,
                              .args = {(long)&_set, (long)&_info,
                                       timeout ? (long)&_remaining : 0,
                                       sizeof(kernel_sigset_t)},
                              .temporary = sig_logical_sigmask,
                              .orig = sig_logical_sigmask,
                              .entry_guard = true};
    _actual = sig_filter_logical_sigmask();
    _call.entry_mask = _actual;
    sig_unlock_rt_sigaction(&sig_fset);
    _res = sig_raw_rt_sigtimedwait(&_call);
    sig_lock_rt_sigaction(&_actual);
    sig_sync_logical_sigmask(_actual);
    if (_res > 0) {
      _res = sig_proc_native_sig(_res, &_info);
      if (_res == -EINPROGRESS)
        continue;
      if (_res > 0 && info) {
        const int _err = syscall_copy_user_mem(info, &_info, sizeof(_info));
        if (_err)
          _res = _err;
      }
      break;
    }
    if (_res < 0 && (_res != -EINTR || !_call.swallowed ||
                     sig_forwarded_sigs != _forwarded))
      break;
  }
  syscall_refresh_fd_edges_locked();
  sig_unlock_with_replay(sig_filter_logical_sigmask(), false);
  return _res;
}

/*
 * Signal interception.
 */

static __always_inline int sig_raw_tgkill(pid_t tgid, pid_t thread, int sig) {
  return util_syscall_no_intercept(SYS_tgkill, tgid, thread, sig);
}

static void sig_forward_default_sig(int sig, const siginfo_t *info,
                                    const void *ctx) {
  const int _def = sig_sigdef(sig);
  if (_def == sig_Core || _def == sig_Term)
    log_backtrace_sig(LOG_EMERG);
  if (_def != sig_Core && _def != sig_Term && _def != sig_Stop)
    return; // Ign/Cont need no action; SIGCONT has already resumed the process.

  kernel_sigset_t _oldmask;
  sig_lock_rt_sigaction(&_oldmask);
  const struct kernel_sigaction _default = {.kernel_sa_handler = SIG_DFL};
  struct kernel_sigaction _saved;
  log_verify(
      !patcher_syscall_err_code(sig_raw_rt_sigaction(sig, &_default, &_saved)));
  const pid_t _pid = _overlaysys_syscall_self_pid > 0
                         ? _overlaysys_syscall_self_pid
                         : internal_raw_getpid();
  log_verify(!patcher_syscall_err_code(
      sig_raw_tgkill(_pid, _overlaysys_syscall_self_tid, sig)));
  const kernel_sigset_t _sig = {.__val = {1UL << (sig - 1)}};
  /*
   * Keep every other signal blocked while holding the lock. SIGCONT resumes a
   * stopped process even when blocked, so its handler runs after unlock.
   */
  log_verify(!patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_UNBLOCK, &_sig, NULL)));

  /*
   * Preserve the latest action, including a replacement installed by the hook.
   */
  log_verify(
      !patcher_syscall_err_code(sig_raw_rt_sigaction(sig, &_saved, NULL)));
  sig_unlock_action(&_oldmask, true);
}

/*
 * Dispatch the current invocation's captured action with the supplied tuple.
 * Automatic inhibition does not gate this call, and forward is left unchanged.
 *
 * The first one-shot call resolves the action; further manual calls repeat that
 * resolution even if another action has since been installed for the signal.
 */
static void sig_call_orig_sig(int sig, siginfo_t *info, void *ctx) {
  struct sig_call *const _call =
      atomic_load_explicit(&sig_current_sig_call, memory_order_acquire);
  if (!_call || _call->sig != sig || _call->info != info || _call->ctx != ctx)
    return;
  if (_call->action.kernel_sa_handler == SIG_IGN)
    return;
  /*
   * Forget the entire continuation chain before application code: a nonlocal
   * exit may abandon outer hooks as well as this frame.
   */
  atomic_store_explicit(&sig_current_sig_call, NULL, memory_order_release);

  if (_call->action.kernel_sa_handler != SIG_DFL) {
    kernel_sigset_t _before_handler;
    sig_lock_rt_sigaction(&_before_handler);
    if (_call->reset_capture) {
      struct sig_reset_state *const _registration =
          _call->reset_capture->registration;
      if (_registration->claimed) {
        _call->action.kernel_sa_handler = SIG_DFL;
        _call->extra.restartable = true;
      } else {
        _registration->claimed = true;
        /*
         * Claim the captured registration without resetting a newer one.
         */
        if (sig_reset_registrations[sig] == _registration) {
          sig_orig_ksa[sig].kernel_sa_handler = SIG_DFL;
          const struct kernel_sigaction _reset =
              sig_wrap_sigaction(sig, &sig_orig_ksa[sig]);
          log_verify(!patcher_syscall_err_code(
              sig_raw_rt_sigaction(sig, &_reset, NULL)));
          sig_record_sigaction(sig, &_reset);
          sig_reset_registrations[sig] = NULL;
          sig_release_reset_registration(_registration);
        }
      }
      sig_release_reset_capture(_call->reset_capture);
      _call->reset_capture = NULL;
    }
    if (_call->action.kernel_sa_handler == SIG_DFL)
      sig_unlock_rt_sigaction(&_before_handler);
    else {
      const unsigned long _bit = 1UL << (sig - 1);
      /*
       * Restore this signal's captured self-deferral. Hook changes to other
       * mask bits still apply during the original handler.
       */
      kernel_sigset_t _active_mask = sig_logical_sigmask;
      _active_mask.__val[0] = (_active_mask.__val[0] & ~_bit) |
                              (_call->handler_mask.__val[0] & _bit);
      sig_set_logical_sigmask(_active_mask);
      _before_handler = sig_filter_logical_sigmask();
      const bool _cb = atomic_exchange_explicit(&syscall_user_cb_active, false,
                                                memory_order_relaxed);
      ++sig_forwarded_sigs;
      if (!(_call->action.sa_flags & SA_RESTART))
        ++sig_nonrestart_sigs;
      sig_unlock_rt_sigaction(&_before_handler);
      const struct cb_errno_scope _handler_errno_scope =
          internal_handler_errno_enter();
      if (_call->action.sa_flags & SA_SIGINFO)
        _call->action.kernel_sa_sigaction(sig, info, ctx);
      else
        _call->action.kernel_sa_handler(sig);
      internal_handler_errno_leave(_handler_errno_scope);
      atomic_store_explicit(&syscall_user_cb_active, _cb, memory_order_relaxed);
    }
  }
  if (_call->action.kernel_sa_handler == SIG_DFL) {
    if (sig_sigdef(sig) == sig_Core || sig_sigdef(sig) == sig_Term ||
        sig_sigdef(sig) == sig_Stop)
      ++sig_forwarded_sigs;
    sig_forward_default_sig(sig, info, ctx);
  }

  /*
   * Reconnect this continuation only after a normal handler/default return.
   */
  atomic_store_explicit(&sig_current_sig_call, _call, memory_order_release);
}

/*
 * Installed with SA_SIGINFO: info/context belong to a real kernel frame.
 * Snapshot the action before the hook; manual and automatic dispatch are
 * independent.
 *
 * Eligible deferred records become pending after a nonzero hook decision. Their
 * later delivery invokes the current hook again with the saved siginfo.
 */
static void sig_sighand_wrapper(int sig, siginfo_t *info, void *ctx) {
  const struct cb_errno_scope _errno_scope = internal_hook_errno_enter();
  kernel_sigset_t _entry_mask;
  sig_lock_rt_sigaction(&_entry_mask);
  kernel_sigset_t _actual_prev;
  __builtin_memcpy(&_actual_prev, &((ucontext_t *)ctx)->uc_sigmask,
                   sizeof(_actual_prev));
  bool _before_wait;
  struct wait_call *const _wait = sig_interrupted_wait(ctx, &_before_wait);
  const uintptr_t _entry_pc = ((ucontext_t *)ctx)->uc_mcontext.gregs[REG_RIP];
  const bool _read_restart =
      _wait && _wait->num == SYS_read &&
      (_before_wait || _entry_pc == sig_wait_syscall_return_pc - 2);
  const unsigned long _forwarded = sig_forwarded_sigs;
  if (_wait) {
    _wait->intercepted = true;
    if (_wait->native) {
      /* The kernel owns the return mask; only inhibited bits are hidden. */
      _wait->orig.__val[0] =
          _actual_prev.__val[0] |
          (_wait->orig.__val[0] &
           atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed));
    }
    sig_set_logical_sigmask(_before_wait ? _wait->orig : _wait->temporary);
  } else
    sig_sync_logical_sigmask(_actual_prev);
  const kernel_sigset_t _prev = sig_logical_sigmask;
  const unsigned long _delivery_ctx = sig_deferred_ctx;
  bool _replay = false;
  int _forward = 1;
  const unsigned long _bit = 1UL << (sig - 1);
  const bool _was_blocked = _prev.__val[0] & _bit;
  struct sig_deferred_sig *const _deferred =
      sig_begin_deferred_delivery(sig, info, _was_blocked, &_replay, &_forward);
  const struct kernel_sigaction _orig_ksa = sig_orig_ksa[sig];
  const unsigned long _discard_epoch = sig_discard_epoch[sig];
  struct sig_reset_state *_reset_capture = NULL;
  if ((_orig_ksa.sa_flags & SA_RESETHAND) &&
      _orig_ksa.kernel_sa_handler != SIG_DFL &&
      _orig_ksa.kernel_sa_handler != SIG_IGN) {
    if (!sig_reset_registrations[sig]) {
      sig_reset_registrations[sig] =
          sig_alloc_reset_state(SIG_RESET_REGISTRATION);
      log_verify(sig_reset_registrations[sig]);
    }
    _reset_capture = sig_capture_reset_registration(sig);
  }
  ucontext_t *const _ctx = ctx;

  kernel_sigset_t _handler_mask = _prev;
  _handler_mask.__val[0] |= _orig_ksa.sa_mask.__val[0];
  if (!(_orig_ksa.sa_flags & SA_NODEFER))
    _handler_mask.__val[0] |= _bit;
  kernel_sigset_t _hook_mask = _handler_mask;
  _hook_mask.__val[0] |= _bit;
  sig_set_logical_sigmask(_hook_mask);

  /*
   * Expose the logical return mask, not an interrupted wait's temporary mask.
   */
  __builtin_memcpy(&_ctx->uc_sigmask, _wait ? &_wait->orig : &_prev,
                   sizeof(_prev));
  _entry_mask = sig_filter_logical_sigmask();
  _entry_mask.__val[0] |= _bit;
  sig_unlock_rt_sigaction(&_entry_mask);

  struct sig_call _call = {
      .sig = sig,
      .info = info,
      .ctx = ctx,
      .action = _orig_ksa,
      .handler_mask = _handler_mask,
      .delivery_mask = _prev,
      .reset_capture = _reset_capture,
      .discard_epoch = _discard_epoch,
      .extra = {.orig_handler = sig_call_orig_sig,
                .inhibit_orig = _deferred || _was_blocked ||
                                _orig_ksa.kernel_sa_handler == SIG_IGN ||
                                (_orig_ksa.kernel_sa_handler == SIG_DFL &&
                                 (sig_sigdef(sig) == sig_Ign ||
                                  sig_sigdef(sig) == sig_Cont)),
                .restartable = _orig_ksa.kernel_sa_handler == SIG_DFL ||
                               (_orig_ksa.sa_flags & SA_RESTART)}};
  struct sig_call *const _prev_call =
      atomic_load_explicit(&sig_current_sig_call, memory_order_acquire);
  atomic_store_explicit(&sig_current_sig_call, &_call, memory_order_release);
  internal_restore_app_errno();
  if (!_replay || _forward)
    hook_dispatch_sig_hooks(sig, info, ctx, &_forward, &_call.extra);
  internal_restore_app_errno();

  /*
   * A captured arrival must reach its consumer's safe point. Do not let a
   * kernel-restarted connect/accept or mutex wait re-enter our raw backend
   * indefinitely. The same pre-entry cancellation is valid before that syscall
   * has run; completed syscall results have a different instruction pointer.
   */
  greg_t *const _registers = _ctx->uc_mcontext.gregs;
  if (_call.captured && !_wait &&
      (uintptr_t)_registers[REG_RIP] == sig_wait_syscall_return_pc - 2) {
    const long _num = _registers[REG_RAX];
    const int _op = (int)_registers[REG_RSI] & FUTEX_CMD_MASK;
    if (_num == SYS_connect || _num == SYS_accept || _num == SYS_accept4 ||
        (_num == SYS_futex &&
         (_op == FUTEX_WAIT || _op == FUTEX_WAIT_BITSET ||
          _op == FUTEX_LOCK_PI || _op == FUTEX_LOCK_PI2))) {
      _registers[REG_RAX] = -EINTR;
      _registers[REG_RIP] = sig_wait_syscall_return_pc;
    }
  }

  if (_deferred && sig_deferred_ctx == _delivery_ctx) {
    kernel_sigset_t _after_hook;
    sig_lock_rt_sigaction(&_after_hook);
    _deferred->info = *info;
    _deferred->forward = _forward;
    --_deferred->active_hooks;
    sig_coalesce_deferred(sig);
    syscall_refresh_fd_edges_locked();
    sig_unlock_rt_sigaction(&_after_hook);
  }

  if (!_deferred && _forward && !_was_blocked &&
      _orig_ksa.kernel_sa_handler != SIG_IGN) {
    /*
     * A manual one-shot dispatch already resolved this frame's registration.
     * Automatic forwarding is a separate delivery and now uses SIG_DFL.
     */
    if (_reset_capture && !_call.reset_capture) {
      _call.action.kernel_sa_handler = SIG_DFL;
      _call.extra.restartable = true;
    }
    sig_call_orig_sig(sig, info, ctx);
  }
  atomic_store_explicit(&sig_current_sig_call, _prev_call,
                        memory_order_release);

  kernel_sigset_t _return_mask;
  __builtin_memcpy(&_return_mask, &_ctx->uc_sigmask, sizeof(_return_mask));
  kernel_sigset_t _current_mask;
  sig_lock_rt_sigaction(&_current_mask);
  sig_release_reset_capture(_call.reset_capture);
  if (_wait && sig_deferred_ctx == _delivery_ctx) {
    _wait->orig = _return_mask;
    _wait->swallowed = !_call.captured && sig_forwarded_sigs == _forwarded;
    if (_wait->swallowed && _wait->num != SYS_read && !_wait->native)
      _return_mask = _wait->temporary;
    if (_read_restart ||
        (_before_wait && (_call.captured || _wait->saved_dispatch))) {
      _wait->entry_restored = true;
      if (_wait->num == SYS_read)
        _wait->temporary = _wait->orig;
      /*
       * A pre-entry handler does not interrupt read. A kernel restart retains
       * the earlier generation so a wrapped nonrestart handler yields EINTR.
       */
      if (_before_wait)
        _wait->read_generation = sig_nonrestart_sigs;
      /*
       * Restarted reads recheck their queue. Captured or explicitly replayed
       * signals must not disappear in the interval before another wait.
       */
      _ctx->uc_mcontext.gregs[REG_RAX] = -EINTR;
      if (_before_wait) {
        if (_entry_pc >= sig_wait_syscall_entry_pc &&
            _entry_pc <= sig_wait_syscall_return_pc)
          _ctx->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t);
        _ctx->uc_mcontext.gregs[REG_RIP] = (uintptr_t)sig_wait_syscall_return;
      } else
        _ctx->uc_mcontext.gregs[REG_RIP] = sig_wait_syscall_return_pc;
      _wait->read_interrupted = true;
    }
  }
  sig_set_logical_sigmask(_return_mask);
  _return_mask = sig_filter_logical_sigmask();
  const unsigned long _current_inhibit =
      atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed);
  _current_mask.__val[0] &= ~_current_inhibit;
  /*
   * Hand the next same-signal frame to rt_sigreturn, after this stack frame is
   * gone, instead of growing an unbounded nest while draining a burst.
   */
  _current_mask.__val[0] |= _bit;
  __builtin_memcpy(&_ctx->uc_sigmask, &_return_mask, sizeof(_return_mask));
  sig_unlock_with_replay(_current_mask, true);

  internal_hook_errno_leave(_errno_scope);
}

/*
 * Explicit initialization/child setup: retain an existing kernel alternate
 * stack, otherwise allocate one owned by this thread and released on
 * intercepted thread exit.
 */
int sig_init_defsigaltstack() {
  const int _saved_errno = errno;
  kernel_sigset_t _oldmask;
  int _err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &_oldmask));
  if (_err) {
    errno = _err;
    return -1;
  }
  stack_t _oss;
  _err = patcher_syscall_err_code(sig_raw_sigaltstack(NULL, &_oss));
  if (!_err && _oss.ss_flags == SS_DISABLE) {
    const size_t _size = sig_enable_defsigaltstack;
    void *const _mapping =
        internal_raw_mmap(NULL, _size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    _err = patcher_syscall_err_code((long)_mapping);
    if (!_err) {
      const stack_t _ss = {
          .ss_size = _size,
          .ss_sp = _mapping,
          .ss_flags = sig_enable_sigaltstackautodisarm ? SIG_SS_AUTODISARM : 0,
      };
      _err = patcher_syscall_err_code(sig_raw_sigaltstack(&_ss, NULL));
      if (_err)
        internal_raw_munmap(_mapping, _size);
      else
        sig_defsigstk = _mapping;
    }
  }
  const int _restore_err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &_oldmask, NULL));
  if (!_err)
    _err = _restore_err;
  errno = _err ? _err : _saved_errno;
  return _err ? -1 : 0;
}

/*
 * Public variables and functions.
 */

/*
 * Public policy APIs use fallible critical sections. Preserve the caller's
 * interception state even when invoked inside a user callback or cleanup path.
 */

int sig_lock_sig_scope(struct sig_lock_scope *scope) {
  scope->saved_errno = errno;
  int _err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &scope->mask));
  if (_err)
    return _err;
  scope->internal = atomic_exchange_explicit(&syscall_internal_emulation, true,
                                             memory_order_relaxed);
  if (!usersched_lock_pi2(&sig_rt_sigaction_lock, _overlaysys_syscall_self_tid,
                          USERSCHED_LOCK_RESTART | USERSCHED_LOCK_NOEAGAIN |
                              FUTEX_PRIVATE_FLAG,
                          100 * usersched_tsc_1us, NULL))
    return 0;
  _err = errno;
  atomic_store_explicit(&syscall_internal_emulation, scope->internal,
                        memory_order_relaxed);
  sig_raw_rt_sigprocmask(SIG_SETMASK, &scope->mask, NULL);
  return _err;
}

/* Always attempt both lock release and mask restoration; retain first error. */
int sig_unlock_sig_scope(const struct sig_lock_scope *scope, int err) {
  if (usersched_unlock_pi(&sig_rt_sigaction_lock, _overlaysys_syscall_self_tid,
                          FUTEX_PRIVATE_FLAG) &&
      !err)
    err = errno;
  atomic_store_explicit(&syscall_internal_emulation, scope->internal,
                        memory_order_relaxed);
  const int _err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &scope->mask, NULL));
  if (!err)
    err = _err;
  errno = err ? err : scope->saved_errno;
  return err ? -1 : 0;
}

/* Signals are blocked; public queue heads must belong to the current thread. */
static bool sig_owns_capture(const struct sigctx *saved) {
  struct sigctx *_current =
      atomic_load_explicit(&sig_saved_head, memory_order_relaxed);
  while (_current && _current != saved)
    _current = _current->next;
  return _current && _current->pid == internal_raw_getpid() &&
         _current->tid == _overlaysys_syscall_self_tid;
}

/* Retire an owned queue before any fallible unmap or application callback. */
static void sig_retire_captured(struct sigctx *saved) {
  while (saved) {
    struct sigctx *const _next = saved->queue_next;
    if (saved->previous)
      saved->previous->next = saved->next;
    else
      atomic_store_explicit(&sig_saved_head, saved->next, memory_order_relaxed);
    if (saved->next)
      saved->next->previous = saved->previous;
    saved->next = sig_retired_head;
    sig_retired_head = saved;
    saved = _next;
  }
}

/* Failed cleanup remains internally owned, without advertising a capture. */
static int sig_reclaim_captured(void) {
  int _first_err = 0;
  struct sigctx **_link = &sig_retired_head;
  while (*_link) {
    struct sigctx *const _saved = *_link;
    struct sigctx *const _next = _saved->next;
    const int _err =
        patcher_syscall_err_code(internal_raw_munmap(_saved, sizeof(*_saved)));
    if (_err) {
      if (!_first_err)
        _first_err = _err;
      _link = &_saved->next;
    } else
      *_link = _next;
  }
  return _first_err;
}

int overlaysys_sig_capture(sigctx_t **restrict queue) noexcept {
  const int _saved_errno = errno;
  struct sig_call *const _call =
      atomic_load_explicit(&sig_current_sig_call, memory_order_acquire);
  int _err = 0;
  if (!queue || !_call)
    _err = EINVAL;
  else if (_call->captured)
    _err = EALREADY;
  else if (_call->extra.inhibit_orig)
    _err = EAGAIN;
  else if (_call->info->si_code > 0 &&
           !(_call->sig == SIGBUS && _call->info->si_code == BUS_MCEERR_AO) &&
           (_call->sig == SIGSEGV || _call->sig == SIGBUS ||
            _call->sig == SIGILL || _call->sig == SIGFPE ||
            _call->sig == SIGTRAP || _call->sig == SIGSYS))
    _err = EOPNOTSUPP;
  if (_err) {
    errno = _err;
    return -1;
  }

  kernel_sigset_t _mask;
  _err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &_mask));
  if (_err) {
    errno = _err;
    return -1;
  }
  struct sigctx *const _head = __atomic_load_n(queue, __ATOMIC_RELAXED);
  struct sigctx *_saved = NULL, *_tail = NULL;
  if (_head && !sig_owns_capture(_head))
    _err = EPERM;
  else
    _saved = internal_raw_mmap(NULL, sizeof(*_saved), PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (!_err)
    _err = patcher_syscall_err_code((long)_saved);
  if (!_err) {
    *_saved = (struct sigctx){
        .next = atomic_load_explicit(&sig_saved_head, memory_order_relaxed),
        .queue_tail = _saved,
        .info = *_call->info,
        .delivery_mask = _call->delivery_mask,
        .discard_epoch = _call->discard_epoch,
        .pid = internal_raw_getpid(),
        .tid = _overlaysys_syscall_self_tid};
    _saved->info.si_signo = _call->sig;
    if (_saved->next)
      _saved->next->previous = _saved;
    atomic_store_explicit(&sig_saved_head, _saved, memory_order_relaxed);
    _call->captured = true;
    if (_head) {
      _tail = _head->queue_tail;
      _tail->queue_next = _saved;
      _head->queue_tail = _saved;
    }
    /* A nested signal can append as soon as the physical mask is restored. */
    __atomic_store_n(queue, _head ? _head : _saved, __ATOMIC_RELEASE);
  }
  const int _restore_err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &_mask, NULL));
  if (!_err && _restore_err) {
    _err = _restore_err;
    _call->captured = false;
    if (_head) {
      _tail->queue_next = NULL;
      _head->queue_tail = _tail;
    }
    __atomic_store_n(queue, _head, __ATOMIC_RELEASE);
    sig_retire_captured(_saved);
    sig_reclaim_captured();
  }
  if (_err) {
    errno = _err;
    return -1;
  }
  errno = _saved_errno;
  return 0;
}

int overlaysys_sig_submit(sigctx_t **restrict queue) noexcept {
  if (!queue) {
    errno = EINVAL;
    return -1;
  }
  if (atomic_load_explicit(&sig_current_sig_call, memory_order_acquire)) {
    errno = EDEADLK;
    return -1;
  }
  struct sig_lock_scope _scope;
  int _err = sig_lock_sig_scope(&_scope);
  if (_err) {
    errno = _err;
    return -1;
  }
  struct sigctx *const _head = __atomic_load_n(queue, __ATOMIC_ACQUIRE);
  if (!_head)
    return sig_unlock_sig_scope(&_scope, 0);
  if (!sig_owns_capture(_head))
    return sig_unlock_sig_scope(&_scope, EPERM);

  /* Stage the entire selected queue; failures leave it caller-owned. */
  const unsigned long _batch = ++sig_deferred_seq;
  unsigned long _claimed = 0;
  for (struct sigctx *_saved = _head; _saved; _saved = _saved->queue_next) {
    struct sig_deferred_sig *const _event =
        sig_remember_deferred(_saved->info.si_signo, &_saved->info, false);
    if (!_event) {
      _err = errno;
      break;
    }
    _event->epoch = _saved->discard_epoch;
    _event->delivery_mask = _saved->delivery_mask;
    _event->captured = true;
    _event->forward = 1;
    _event->batch = _batch;
    _claimed |= 1UL << (_event->sig - 1);
  }
  if (!_err)
    _err = sig_refresh_wrapped_sigactions_res(0);
  if (_err) {
    struct sig_deferred_sig **_link = &sig_deferred_head;
    while (*_link)
      if ((*_link)->captured && (*_link)->batch == _batch)
        sig_release_deferred(_link);
      else
        _link = &(*_link)->next;
    return sig_unlock_sig_scope(&_scope, _err);
  }

  /* No caller-owned records survive into a handler, even after nonlocal exit.
   */
  __atomic_store_n(queue, NULL, __ATOMIC_RELEASE);
  sig_retire_captured(_head);
  const int _cleanup_err = sig_reclaim_captured();
  /* Nested submissions dispatch their own batch, never an outer batch. */
  for (struct sig_deferred_sig *_event = sig_deferred_head; _event;
       _event = _event->next)
    if (_event->captured && _event->batch == _batch)
      _event->active_hooks = 0;
  while (_claimed) {
    sig_coalesce_deferred(__builtin_ctzl(_claimed) + 1);
    _claimed &= _claimed - 1;
  }
  syscall_refresh_fd_edges_locked();
  for (;;) {
    struct wait_call _wait = {.num = SYS_rt_sigsuspend,
                              .orig = sig_logical_sigmask,
                              .saved_dispatch = true};
    bool _pending = false;
    for (const struct sig_deferred_sig *_event = sig_deferred_head; _event;
         _event = _event->next)
      if (_event->captured && _event->batch == _batch) {
        _wait.temporary = _event->delivery_mask;
        _pending = true;
        break;
      }
    if (!_pending)
      break;
    /* Preserve temporary-mask eligibility without retaining an old context. */
    _err = sig_set_logical_sigmask_res(_wait.temporary);
    unsigned long _ready;
    int _postponed = 0;
    if (!_err)
      _err = sig_prepare_deferred_replay_res(&_ready, &_postponed);
    const int _restore_err = sig_set_logical_sigmask_res(_wait.orig);
    if (!_err)
      _err = _postponed ? _postponed : _restore_err;
    if (_err)
      break;
    /* A disposition change can discard the occurrence while preparing replay.
     */
    if (!_ready)
      continue;
    const long _res = sig_run_masked_wait(&_wait);
    if (_res != -EINTR) {
      _err = _res < 0 ? (int)-_res : EIO;
      break;
    }
  }
  _scope.mask = sig_filter_logical_sigmask();
  if (!_err)
    _err = _cleanup_err;
  return sig_unlock_sig_scope(&_scope, _err);
}

void overlaysys_sig_release(sigctx_t **restrict queue) noexcept {
  if (!queue || !__atomic_load_n(queue, __ATOMIC_ACQUIRE))
    return;
  const int _saved_errno = errno;
  kernel_sigset_t _mask;
  int _err = patcher_syscall_err_code(
      sig_raw_rt_sigprocmask(SIG_SETMASK, &sig_fset, &_mask));
  if (!_err) {
    struct sigctx *const _head = __atomic_load_n(queue, __ATOMIC_ACQUIRE);
    if (_head && !sig_owns_capture(_head))
      _err = EPERM;
    else {
      __atomic_store_n(queue, NULL, __ATOMIC_RELEASE);
      sig_retire_captured(_head);
      _err = sig_reclaim_captured();
    }
    const int _restore_err = patcher_syscall_err_code(
        sig_raw_rt_sigprocmask(SIG_SETMASK, &_mask, NULL));
    if (!_err)
      _err = _restore_err;
  }
  errno = _err ? _err : _saved_errno;
}

int overlaysys_sig_set_defsighand(
    const sigset_t *restrict force_hook,
    const sigset_t *restrict inhibit_block) noexcept {
  if (!force_hook && !inhibit_block)
    return 0;
  if (!atomic_load_explicit(&sig_ready, memory_order_acquire)) {
    errno = ENODEV;
    return -1;
  }
  unsigned long _force_hook = 0, _inhibit_block = 0, _eligible = 0;
  for (int i = 1; i < NSIG; ++i) {
    if (i == SIGKILL || i == SIGSTOP || (i > SIGSYS && i < SIGRTMIN))
      continue;
    const unsigned long _bit = 1UL << (i - 1);
    if (sig_exempt_sighand & _bit)
      continue;
    _eligible |= _bit;
    if (force_hook && sigismember(force_hook, i) == 1)
      _force_hook |= _bit;
    if (inhibit_block && sigismember(inhibit_block, i) == 1)
      _inhibit_block |= _bit;
  }
  struct sig_lock_scope _scope;
  int _err = sig_lock_sig_scope(&_scope);
  if (_err) {
    errno = _err;
    return -1;
  }
  kernel_sigset_t _logical = _scope.mask;
  if (sig_logical_sigmask_inited)
    _logical.__val[0] |= sig_logical_sigmask.__val[0] & sig_suppressed_sigmask;
  _err = sig_set_logical_sigmask_res(_logical);
  if (_err)
    return sig_unlock_sig_scope(&_scope, _err);

  const unsigned long _old_force =
      atomic_load_explicit(&sig_force_sighand, memory_order_relaxed);
  const unsigned long _old_inhibit =
      atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed);
  /* Preserve omitted policies under the lock so independent updates compose. */
  if (!force_hook)
    _force_hook = _old_force;
  if (!inhibit_block)
    _inhibit_block = _old_inhibit;
  /* Environment-selected policies remain enabled for every eligible signal. */
  if (sig_env_sighand >= 1)
    _force_hook = _eligible;
  if (sig_env_sighand == 2)
    _inhibit_block = _eligible;
  /* Native libc sigaction rejects its reserved thread-management signals. */
  unsigned long _selected = (_force_hook | _inhibit_block | _old_force |
                             _old_inhibit | sig_wrapped_sighand) &
                            _eligible;
  struct kernel_sigaction _actions[NSIG];
  for (int i = 1; i < NSIG; ++i) {
    const unsigned long _bit = 1UL << (i - 1);
    if (!(_selected & _bit))
      continue;
    const int _res =
        patcher_syscall_err_code(sig_raw_rt_sigaction(i, NULL, &_actions[i]));
    if (_res) {
      if (!_err)
        _err = _res;
      _force_hook = (_force_hook & ~_bit) | (_old_force & _bit);
      _inhibit_block = (_inhibit_block & ~_bit) | (_old_inhibit & _bit);
      _selected &= ~_bit;
      continue;
    }
    if (_actions[i].kernel_sa_sigaction == sig_sighand_wrapper) {
      _actions[i] = sig_orig_ksa[i];
    } else {
      sig_wrapped_sighand &= ~_bit;
      sig_forced_restart &= ~_bit;
    }
  }

  atomic_store_explicit(&sig_force_sighand, _force_hook, memory_order_release);
  atomic_store_explicit(&sig_inhibit_sigblock, _inhibit_block,
                        memory_order_release);
  const unsigned long _requested_inhibit = _inhibit_block;
  for (int i = 1; i < NSIG; ++i) {
    const unsigned long _bit = 1UL << (i - 1);
    if (!(_selected & _bit))
      continue;
    const struct kernel_sigaction _ksa = sig_wrap_sigaction(i, &_actions[i]);
    struct sigaction _sa = {.sa_sigaction = _ksa.kernel_sa_sigaction,
                            .sa_flags = _ksa.sa_flags,
                            .sa_restorer = _ksa.sa_restorer};
    __builtin_memcpy(&_sa.sa_mask, &_ksa.sa_mask, sizeof(kernel_sigset_t));
    const struct kernel_sigaction _prev = sig_orig_ksa[i];
    sig_orig_ksa[i] = _actions[i];
    if (sigaction(i, &_sa, NULL)) {
      if (!_err)
        _err = errno;
      sig_orig_ksa[i] = _prev;
      _force_hook = (_force_hook & ~_bit) | (_old_force & _bit);
      _inhibit_block = (_inhibit_block & ~_bit) | (_old_inhibit & _bit);
      atomic_store_explicit(&sig_force_sighand, _force_hook,
                            memory_order_release);
      atomic_store_explicit(&sig_inhibit_sigblock, _inhibit_block,
                            memory_order_release);
      continue;
    }
    const int _res = sig_record_sigaction_res(i, &_ksa);
    if (!_err)
      _err = _res;
  }

  /* A rejected inhibit change can affect earlier successful actions' masks. */
  int _res =
      sig_refresh_wrapped_sigactions_res(_requested_inhibit ^ _inhibit_block);
  if (!_err)
    _err = _res;
  _scope.mask = sig_filter_logical_sigmask();
  unsigned long _ready;
  int _postponed;
  _res = sig_prepare_deferred_replay_res(&_ready, &_postponed);
  if (!_err)
    _err = _postponed ? _postponed : _res;
  return sig_unlock_sig_scope(&_scope, _err);
}

int overlaysys_sig_get_defsighand(sigset_t *restrict force_hook,
                                  sigset_t *restrict inhibit_block) noexcept {
  if (!force_hook && !inhibit_block)
    return 0;
  if (!atomic_load_explicit(&sig_ready, memory_order_acquire)) {
    errno = ENODEV;
    return -1;
  }
  struct sig_lock_scope _scope;
  const int _err = sig_lock_sig_scope(&_scope);
  if (_err) {
    errno = _err;
    return -1;
  }
  const unsigned long _force_hook =
      atomic_load_explicit(&sig_force_sighand, memory_order_relaxed);
  const unsigned long _inhibit_block =
      atomic_load_explicit(&sig_inhibit_sigblock, memory_order_relaxed);
  if (sig_unlock_sig_scope(&_scope, 0))
    return -1;

  if (force_hook) {
    *force_hook = (sigset_t){0};
    __builtin_memcpy(force_hook, &_force_hook, sizeof(_force_hook));
  }
  if (inhibit_block) {
    *inhibit_block = (sigset_t){0};
    __builtin_memcpy(inhibit_block, &_inhibit_block, sizeof(_inhibit_block));
  }
  return 0;
}

/*
 * Core state and initialization-time exemptions must be ready before this call.
 */
int sig_init_env() {
  static bool _configured, _stack_ready, _policy_ready;
  if (!_configured) {
    const char *const _pedantic = getenv("OVERLAYSYS_PEDANTIC");
    const char *const _stack = getenv("OVERLAYSYS_DEFSIGALTSTACK");
    const char *const _sighand = getenv("OVERLAYSYS_DEFSIGHAND");
    if ((_pedantic && strcmp(_pedantic, "0") && strcmp(_pedantic, "1")) ||
        (_sighand && strcmp(_sighand, "1") && strcmp(_sighand, "2"))) {
      errno = EINVAL;
      return -1;
    }
    size_t _stack_size = 0;
    if (_stack) {
      char *_end;
      errno = 0;
      if (_stack[0] == '-') {
        errno = EINVAL;
        return -1;
      }
      _stack_size = strtoul(_stack, &_end, 0);
      if (errno)
        return -1;
      if (_end == _stack || *_end) {
        errno = EINVAL;
        return -1;
      }
      const long _min = sysconf(_SC_SIGSTKSZ);
      if (_min < 0) {
        if (!errno)
          errno = EINVAL;
        return -1;
      }
      if (_stack_size < (size_t)_min) {
        errno = EINVAL;
        return -1;
      }
    }
    /* Freeze validated options once effects begin; retry only unfinished work.
     */
    sig_pedantic = _pedantic && _pedantic[0] == '1';
    sig_enable_sigaltstackautodisarm =
        !!getenv("OVERLAYSYS_SIGALTSTACKAUTODISARM");
    sig_enable_sigaltstackeperm = !!getenv("OVERLAYSYS_SIGALTSTACKEPERM");
    sig_enable_defsigaltstack = _stack_size;
    sig_env_sighand = _sighand ? _sighand[0] - '0' : 0;
    _configured = true;
  }
  if (!_stack_ready) {
    if (sig_enable_defsigaltstack && sig_init_defsigaltstack())
      return -1;
    _stack_ready = true;
  }
  if (!_policy_ready) {
    if (sig_env_sighand) {
      sigset_t _all;
      if (sigfillset(&_all) || overlaysys_sig_set_defsighand(
                                   &_all, sig_env_sighand == 2 ? &_all : NULL))
        return -1;
    }
    _policy_ready = true;
  }
  return 0;
}
