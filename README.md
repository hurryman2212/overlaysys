# OverlaySys

## Overview

OverlaySys is a Linux x86-64 syscall and signal interception library with an
internal engine derived from
[syscall_intercept](https://github.com/pmem/syscall_intercept). Its C API lets
hooks replace syscalls and control signal delivery. Thread-local storage (TLS)
guards prevent direct syscall-hook reentry while retaining required emulation.
Signal delivery and fork/clone preserve the distinction between hook and
application execution. Internal emulation maintains logical signal actions and
masks, including temporary blocking during I/O multiplexing waits, pending
deliveries, and signalfd/epoll state.

## Explicit patching

Loading or linking OverlaySys allocates its shared hook registry through a
constructor, without patching instructions. The caller selects when to activate
interception:

```c
if (overlaysys_hook_insert(OVERLAYSYS_HOOK_TYPE_SYSCALL, my_hook, -1, false) == -1 ||
    overlaysys_patch_all(0, NULL) == -1)
    perror("OverlaySys initialization");
```

The public header also provides two explicit initialization shortcuts:

```c
OVERLAYSYS_INIT();      /* All eligible loaded libraries. */
OVERLAYSYS_INIT_LIBC(); /* libc.so* and libpthread.so*, skipping missing entries. */
```

`overlaysys_patch_all(len, inhibit_patch)` examines the shared libraries loaded
in OverlaySys's linker namespace at that call. It skips the specified matches
and protected runtime objects. `overlaysys_patch(len, paths, skip_missing)`
patches the union of matches for its path array. Both arrays are read-only.
Overlapping and duplicate entries are validated separately, but each load
instance is processed once. Neither call loads a missing target or automatically
intercepts later `dlopen()` calls. Invoke either API again to include newly
loaded libraries.

```c
const char *const paths[] = {"libc.so*", "libpthread.so*"};
overlaysys_patch(2, paths, true);
```

For `patch`, with `skip_missing=false`, every entry must match a currently
loaded object; existing files that are not loaded do not satisfy the request.
With `true`, missing paths and entries with no loaded match are skipped.
`patch_all` always ignores missing exclusion entries and has no such flag. Both
functions return 0 on success or -1 with errno on failure. Success preserves the
caller's errno. Invalid inputs, permission errors and patch failures are
reported without terminating the process. Missing means ENOENT/ENOTDIR during
input path resolution, or no loaded match; it does not include a selected
object's backing ELF becoming unavailable later. Required matches are checked
before instructions are changed.

Both functions accept `len=0` with a NULL array. For `patch`, this selects no
objects but still prepares the runtime on the first call. For `patch_all`, it
means no exclusions. `OVERLAYSYS_INIT()` calls `patch_all(0, NULL)`;
`OVERLAYSYS_INIT_LIBC()` is a GNU C/C++ expression macro that calls `patch` with
the two patterns above and `skip_missing=true`. Both initialization macros
return the underlying 0/-1 result.

Names without `/`, such as `libexample.so`, match every loaded library with that
basename in its loader-recorded path, including different files loaded from
different directories. `*` matches zero or more bytes, so `libc.so*` selects
`libc.so.6`, and `libexample*.so` can select several library names. Basename
patterns also match leading dots. Other characters, including `?`, brackets and
backslashes, are literal.

Paths containing `/` identify files: paths beginning with `/` are absolute, and
other paths are relative to the working directory at the API call. Use
`./libexample.so` to select a file in the current directory. Patterns such as
`/opt/plugins/*.so` or `./plugins/*.so` expand to filesystem entries and select
only loaded regular files. In filesystem patterns, a leading dot must be written
explicitly in that path component. `*` cannot cross `/`; `**` has no recursive
directory meaning. Directories, other nonregular files and dangling symlinks
found by a wildcard are ignored. Other filesystem lookup errors are returned.

File-path selection compares the mapped file's device and inode, so symlinks and
hard links identify the same file, and changing the working directory after
loading a library does not change its identity. Neither form searches for
unloaded libraries through `LD_LIBRARY_PATH` or loads a matching file.

The same matching rules apply to `inhibit_patch`. Exclusions may match protected
or already patched objects. Missing names, files and patterns in this list are
ignored:

```c
const char *const inhibit_patch[] = {"libskip*.so", "./plugins/private/*.so"};
overlaysys_patch_all(sizeof(inhibit_patch) / sizeof(inhibit_patch[0]),
                    inhibit_patch);
```

Patching is irreversible. Repeated calls leave completed load instances
unchanged. Exclusions apply only to the current call: an excluded library can be
selected later, and excluding an already patched library does not undo its
patches. Objects with no syscall instructions are processed successfully.
Selected libraries are retained through loader references until process exit;
`dlclose()` does not unload them or run their final destructors while those
references remain. Selected objects may remain retained after a failed call as
well.

The registry distinguishes preparation, written text and completion. Failures
before text changes retain or release preparation resources safely; retries
first finish failed cleanup and then rebuild preparation. If writing succeeds
but restoring RX protection fails, the written code, trampoline, metadata and
loader reference remain alive. That object's status stays incomplete, and retry
attempts only the RX restoration. Earlier completed objects in a batch remain
active. Keep affected code inactive while resolving an error and retrying; an
error is neither rollback nor permission to resume execution of incomplete
objects. Pages may remain writable after such an error. A kernel refusal to
restore temporary masks or release resources can also leave partial state;
cleanup attempts preserve the first errno.

Errors include EINVAL for invalid arguments/options, ENOENT for required missing
matches, EPERM for protected targets, ENOMEM for allocation failure, ENOEXEC for
invalid or truncated ELF, EOPNOTSUPP for unsupported formats/modes, EOVERFLOW or
ERANGE for size/branch limits, ESTALE for changed mappings, and EBUSY/EDEADLK
for conflicting or reentrant calls. Kernel errors propagate; loader errors use
documented EIO/ELIBACC mappings. Capstone errors are translated explicitly.

`overlaysys_patch_check(path, &check)` queries these completion records using
the same name, file-path and wildcard rules. It returns 0 on a successful query
and writes the completion state to `check`, preserving errno. For a non-NULL
path, `check` is true only when at least one eligible loaded instance matches
and all eligible matches have been processed. Missing, unloaded, unpatched or
exact protected targets yield false without a query error; wildcard queries
ignore protected objects. Objects with no syscall instructions count as
processed. A newly loaded matching library can change true to false until it is
patched. Passing NULL checks every eligible loaded library and yields true when
none remain unpatched, including an empty eligible set. Queries never initialize
the runtime, patch code or retain libraries.

Query failures return -1 with errno and leave `check` unchanged. A NULL output,
empty path or invalid file type sets EINVAL; a query conflicting with an active
patch or query sets EBUSY. Operational lookup and signal-mask errors propagate,
preserving the first error during cleanup. Interception state is restored on
return; failure to restore the physical signal mask is reported and may leave
signals blocked. These failures do not terminate the process. The query uses
libc allocation and loader operations: never call from a signal handler or
reenter allocator/loader critical sections from a hook. Serialize patch/query
calls and keep loader mappings stable.

The main executable, the image containing OverlaySys and its patcher, vDSO, and
the Capstone decoder runtime are protected. OverlaySys identifies its own image
by locating its private implementation address within the actual ELF load
segments, rather than comparing filenames or assuming load biases are unique.
This also covers renamed libraries and static linking into a shared object or a
non-PIE executable. `patch_all` always skips that image. Any `patch` entry
matching it returns -1 with EPERM, including wildcard matches and
`skip_missing=true`. Use `patch_all` for whole-process patching; `"*"` as an
explicit target matches OverlaySys too and is rejected.

Other linker namespaces, including OverlaySys's isolated pthread namespace, are
outside this API. Wildcards may skip other protected objects when they also
match eligible objects. Exact protected targets and protected-only wildcard
targets also return EPERM. These selection restrictions do not change status
queries or path enumeration, which continue to exclude protected objects. The
current x86-64 backend requires a readable, unchanged backing ELF and supports
executable sections in one readable, non-writable executable load segment.
Unsupported layouts, unsafe instruction relocation, invalid arguments and
patching failures return -1 with errno. Only a return value of 0 means the
selected objects completed processing. This does not assert coverage of every
syscall in the process: the main executable, excluded objects, other namespaces,
and code outside the supported ELF sections remain outside that selection.
Anonymous executable mappings and newly generated or modified code are not
discovered through `mmap()`/`mprotect()` hooks or Syscall User Dispatch.

The first patch call prepares OverlaySys state and must occur before thread
creation and before signalfd/epoll relationships requiring emulation are
established. Existing threads and earlier descriptor relationships are not
adopted. This ordering also applies to constructors that run before the first
patch call; simply calling from a constructor does not establish it. Load the
initial targets, register hooks, complete the initial patch, and only then start
application worker threads.

Later calls require the caller to keep affected code inactive and the
loaded-object mappings stable throughout patching and any required retry. No
thread may execute or resume into the bytes being rewritten, including through a
signal handler, a saved signal context, or a return address. Pausing a thread
inside affected code or merely serializing patch calls is insufficient. Finish
`dlopen()` and target constructors before patching, and prevent concurrent
loader changes and signal-handler entry into affected code; do not call a patch
API from a signal handler. Conflicting or reentrant patch calls return
EBUSY/EDEADLK; conflicting patch-status queries return EBUSY. These checks
serialize the API, not application execution. Arbitrary multithreaded live
patching and unpatching are not provided.

Hooks may be registered before activation. Non-noop signal-policy API calls
before state preparation return `-1` with `errno = ENODEV`; both NULL arguments
remain a successful no-op.

`overlaysys_syscall_gettid()` and `overlaysys_syscall_getpid()` read the cached
TID and PID from TLS without a syscall or changing `errno`. Normal hooks and
epilogues run after both caches are populated. Before initialization or after an
early preparation failure, they return zero; bypassing intercepted fork/clone
can leave zero or stale inherited identities.

Use paired `overlaysys_syscall_hook_disable()` and
`overlaysys_syscall_hook_enable()` calls around direct function calls that must
skip user syscall hooks and epilogues. Pairs nest per thread and preserve
`errno` on success. Intercepted syscalls still perform OverlaySys signal,
descriptor, and lifecycle processing; signal hooks and application handlers
remain enabled. An unmatched enable fails with `EINVAL`. The raw
`_overlaysys_syscall()` bypasses this processing and is only for operations that
specifically require bypassing it.

The former `overlaysys_is_allowed()` query and the backend's `INTERCEPT_*`
startup/environment filters are removed. OverlaySys's own policy environment
variables are validated before effects begin. Invalid values can be corrected
and retried; once application starts, validated values are retained while retry
finishes incomplete initialization. Initialization keeps the helper library's
existing/default lock-spin tuning; it does not invoke its optional calibrator,
which can terminate on host errors. Selective patching must still cover the
syscall paths needed by the emulation contracts below; deliberately unpatched
paths bypass their bookkeeping.

The engine's common object selection and lifecycle code lives in `src/patcher/`;
x86-64 decoding, relocation and execution wrappers live in `src/patcher/x86/`.
There is no external `libsyscall_intercept` build or runtime dependency.
Capstone and `x86linuxextra` remain dependencies. Callback name lookup and
call-stack metadata preparation also use elfutils `libdw` and `libelf`
(including their development headers when building).

## Call-stack queries

```c
int overlaysys_callstack_prepare(void) noexcept;
int overlaysys_callstack_check(const void *restrict func_ptr,
                              bool *restrict on_callstack) noexcept;
```

Prepare after loading and patching the initial libraries, outside hooks and
signal handlers, before starting workers. Preparation reads matching ELF files,
copies function ranges and unwind rules, and retains loader references and
immutable metadata until process exit. Repeat it after loading additional
libraries while loading and patching are externally quiescent. Existing records
are reused. The query neither initializes nor refreshes metadata lazily.

The query starts with the caller's saved register state, omitting its own
frames. When unwinding through an ordinary syscall hook, it recognizes the fixed
interception frame and resumes from the original syscall registers. This bridge
adds no instructions to the ordinary interception path. The query uses per-call
stack storage and direct kernel reads of its own process memory; it performs no
allocation, loader/symbol lookup, logging, or shared-lock wait.
`process_vm_readv` must be permitted. Resolve the caller's dynamic binding to
the query before using it inside hooks, either by eager binding or a startup
call.

Return 0 means the query completed and wrote `on_callstack`, preserving errno.
True means a physical frame in the prepared function range was found. False
requires reaching a supported end of the stack. Return -1 sets errno and leaves
the output unchanged: NULL arguments use EINVAL, missing preparation/function or
unwind metadata (including rules that could not be prepared) uses ENODATA,
unsupported operations in a prepared rule use EOPNOTSUPP, and cycle or traversal
limits use ELOOP/EOVERFLOW. Kernel read failures propagate.

Pass an actual function entry with a nonempty, unambiguous ELF symbol range. An
unresolved IFUNC resolver, a PLT stub, or a function's interior address is not a
substitute for its implementation entry. Inlined and tail-eliminated frames,
unrecorded split code regions, and unsupported unwind programs are not
reconstructed. vDSO and generated-code frames without supported metadata remain
unknown; the ordinary OverlaySys syscall bridge is handled explicitly. Keep
prepared code and mappings unchanged. A negative membership result does not
establish reentrancy safety because other functions can hold shared locks or
state. A failed query must not be treated as absence.

## Hook registration

Five independently indexed lists share one API:

```c
ptrdiff_t overlaysys_hook_insert(overlaysys_hook_type_t type, void *handler,
                                ptrdiff_t index, bool replace);
void *overlaysys_hook_get(overlaysys_hook_type_t type, ptrdiff_t index);
void *overlaysys_hook_remove(overlaysys_hook_type_t type, ptrdiff_t index);
int overlaysys_hook_clear(overlaysys_hook_type_t type);
int overlaysys_hook_get_libpath(overlaysys_hook_type_t type, ptrdiff_t index,
                               char *ptr, size_t capacity);
int overlaysys_hook_get_libname(overlaysys_hook_type_t type, ptrdiff_t index,
                               char *ptr, size_t capacity, bool exclude_extension);
int overlaysys_hook_get_name(overlaysys_hook_type_t type, ptrdiff_t index,
                            char *ptr, size_t capacity);
```

| Type                                         | Handler type                         |
| -------------------------------------------- | ------------------------------------ |
| `OVERLAYSYS_HOOK_TYPE_SYSCALL`               | `overlaysys_syscall_hook_t`          |
| `OVERLAYSYS_HOOK_TYPE_SYSCALL_EPILOGUE`      | `overlaysys_syscall_epilogue_t`      |
| `OVERLAYSYS_HOOK_TYPE_SIG`                   | `overlaysys_sig_hook_t`              |
| `OVERLAYSYS_HOOK_TYPE_CLONE_CHILD_EPILOGUE`  | `overlaysys_clone_child_epilogue_t`  |
| `OVERLAYSYS_HOOK_TYPE_CLONE_PARENT_EPILOGUE` | `overlaysys_clone_parent_epilogue_t` |

C and C++ use the same argument order and runtime `type` value:

```c
ptrdiff_t index =
    overlaysys_hook_insert(OVERLAYSYS_HOOK_TYPE_SYSCALL, my_hook, -1, false);
// With registrations unchanged, this returns the same index without appending.
ptrdiff_t same_index =
    overlaysys_hook_insert(OVERLAYSYS_HOOK_TYPE_SYSCALL, my_hook, -1, false);
void *removed = overlaysys_hook_remove(OVERLAYSYS_HOOK_TYPE_SYSCALL, 0);
overlaysys_hook_clear(OVERLAYSYS_HOOK_TYPE_SYSCALL);
```

C callers must match the handler signature to `type`. Function-pointer storage
in `void *` uses the supported Linux x86-64 ABI; implicit conversion in C is a
GNU extension and may trigger `-Wpedantic`. The C++20 template overload deduces
the handler type, accepts compatible `noexcept` functions and noncapturing
lambdas, and rejects unsupported signatures at compile time. A valid handler
signature paired with the wrong runtime `type` fails with `-1` and `EINVAL`.
Passing an erased `void *` directly bypasses that signature check. Removal
returns `void *` in both languages; cast it back to the selected callback type
when needed.

Insertion accepts `0` through the current length, or `-1` for the end. After
validating the type, non-NULL handler, and index, it checks the selected list
for the same callback address. If found, it returns the existing index without
allocating a registration node or changing the list, even if `replace=true`
names another position. Invalid indices still fail, and other lists are
independent. For a callback absent from the selected list, `replace=false`
inserts before that position and shifts later entries. `replace=true` changes an
existing position's handler without shifting entries, changing length,
allocating a node, or growing shared storage. `-1` and the current length append
a new callback in either mode. The old handler's code/state is not freed. The
call returns the existing, inserted, or replaced zero-based index as
`ptrdiff_t`, or `-1` with errno on failure. A new append returns that list's
previous length; check success with `>= 0`. NULL handlers and invalid
types/indices fail with `EINVAL`, and allocation failure reports `ENOMEM`. The
returned index describes the current position, not a stable handle: another
serialized change can shift it before the caller resumes. `get` returns the
current handler without removal; `remove` returns the removed handler. Both use
`-1` to select the last entry and return NULL with `errno = ENOENT` when no
entry exists, including an empty list. Other failures also return NULL with
errno set; callers do not need to clear errno before either function. An invalid
type or index below `-1` sets `EINVAL`. Borrowed callback addresses require
their code and state to remain alive during use. Clear removes the entire
selected list and returns 0, including when already empty, or -1 with errno on
failure. Successful calls preserve errno.

The three string getters inspect the callback at that list's current index; `-1`
selects the last entry. They copy into the caller's buffer and return 0 on
success, preserving errno, or -1 with errno on failure. An absent entry produces
an empty string; a registered callback with no known path/name produces `"?"`.
`capacity` includes the terminating NUL. If the result does not fit, they copy
the first `capacity - 1` bytes and a NUL when capacity is nonzero, then return
-1 with `ENOMEM`. Zero capacity is allowed with a NULL pointer but cannot fit
even an empty string, so it fails with `ENOMEM`. A NULL pointer with nonzero
capacity, an invalid type, or an index below `-1` fails with `EINVAL`. Other
errors leave a valid buffer with nonzero capacity empty. Callers own all result
storage and its lifetime; there are no persistent internal return buffers. The
former loaded-library enumeration API has been removed.

`get_libpath` resolves the callback's actual mapped shared library or executable
to a canonical absolute path, including symlink resolution; loading a relative
path and later changing directory does not change the result. `get_libname`
copies only the filename from that path. With `exclude_extension=true`, it
removes the last dot and its suffix: `libfoo.so.1` becomes `libfoo.so`, while
`.hidden` remains unchanged. A symlink therefore gives the target's filename.

`get_name` checks full/dynamic ELF symbols and elfutils debug sources, including
local/static functions, separate build-ID/`.gnu_debuglink` files, compressed
`.gnu_debugdata`, and DWARF subprogram names with abstract-origin/specification
references. Configured `DEBUGINFOD_URLS` and local caches may also be used.
Unavailable optional debug information falls back to the remaining sources; C++
names are not demangled. Backing ELF files must still match their loaded images
and remain unchanged during lookup; the copied results are independent of those
images afterward.

Queries share the registration mutex with insert/remove/clear, giving each call
a consistent entry snapshot; separate path/name calls can observe different
registrations if a writer intervenes. They require stable loader mappings and
ordinary calling context, never signal or hook/epilogue context (the latter
returns NULL for `get`, or -1 for a string getter, with EDEADLK). String getters
may allocate/read image and debug files and do not add work to callback dispatch
or retain a library reference.

Callbacks run in index order. Syscall and signal chains stop when a hook sets
`forward = 0`; otherwise the next hook runs, followed by internal emulation or
original signal delivery. Eligible syscall and clone epilogues all run in order.
Parent epilogues receive successful child IDs or negative errors, including
pre-kernel rejection; child epilogues run after child state setup. Before each
clone epilogue, `errno` is set to zero on success (always for children) or to
`-child_tid` on clone failure in the parent. Incidental callback errno changes
are discarded. Registration uses x86linuxextra's generic intrusive list;
OverlaySys owns the registration nodes.

A syscall epilogue has this signature:

```c
typedef void (*overlaysys_syscall_epilogue_t)(long num, long a, long b, long c,
                                            long d, long e, long f,
                                            long *orig_ret);
```

It runs only after every syscall hook forwards the call and the operation
returns through the ordinary path in the original context, including internal
emulation. Replaced calls, nested or disabled user syscall dispatch, and all
`clone`/`clone3`/`fork`/`vfork` and `rt_sigreturn` paths are excluded.
Nonreturning calls have no epilogue. The original arguments accompany
`*orig_ret` in libc form: a success value or `-1` with `errno` set to the
positive error code. The value includes earlier epilogues' changes. `orig_ret`
is non-NULL and borrowed for the current callback only; do not retain it after
returning. Before each callback, raw kernel errors in `[-4095, -1]` are
converted to this form; success inputs set `errno` to zero.

Syscall prologue replacement results and syscall epilogue results use the same
libc convention. A prologue reports an error with `errno = EACCES; return -1;`.
An epilogue returns void and updates the pointed-to value: store a success value
in `*orig_ret` to change or recover the result, or set `errno` to a valid
positive native error code and `*orig_ret = -1` to report an error. Raw negative
errors such as `-EACCES` are unsupported callback outputs. Whenever
`*orig_ret == -1`, the callback's `errno` determines the error. To pass through,
leave `*orig_ret` unchanged and preserve `errno` across logging or other calls
if the incoming result is `-1`. Other incidental `errno` changes are ignored. An
epilogue error output with `errno` outside `[1, 4095]` becomes `EINVAL`.

Only the final error updates the application's saved `errno`. If a later
epilogue recovers to success, earlier errors are discarded and the application
retains its prior `errno`, including original signal-handler changes. Epilogues
must return normally; direct intercepted calls they make skip user syscall hooks
and epilogues while keeping required emulation. Changing the result does not
undo the completed operation or its bookkeeping.

The constructor creates `MAP_SHARED` storage for all five lists, nodes,
allocation metadata, and a process-shared writer mutex, even before the first
registration. Fork descendants share subsequent changes in both directions;
process exit leaves surviving registrations intact. Independent loads and `exec`
do not attach to this registry. Only membership is shared: callback code and
state must remain valid at their addresses in every participating process.
Loading a callback library in one process does not load it in the others, and
this registry does not make callback state or signal/emulation policies shared.

Storage grows with registrations and may relocate when it cannot expand in
place. Internal links are translated between process-local mapping bases.
Removal compacts live nodes across all lists and releases unused tail pages;
remove/clear shrink the data mapping to page-rounded live storage, with a
one-page minimum plus one fixed control page. Other processes refresh their
mapping on their next registry API call or dispatch. Idle processes can retain
larger mappings, but successful tail-page reclamation also frees their unused
backing pages. OS failures can defer shrinking/reclamation without undoing a
removal. Dispatch normally takes no registration lock or remapping syscall;
refresh briefly blocks physical signals and serializes local remapping.

A memfd starts at one page and grows on demand before new nodes are mapped;
removal attempts to shrink its logical size along with the mapping. Capacity is
bounded by page-rounded `PTRDIFF_MAX` and the constructor's `RLIMIT_FSIZE`. A
private `CLOEXEC` FD is inherited by fork descendants and permits growth without
extra capabilities. Intercepted `close` treats it as private, `close_range`
preserves it, and `dup2`/`dup3` relocates it before replacement. Its descriptor
number follows each process or thread's FD table. Raw FD operations that bypass
interception must not close or replace library-owned descriptors. Closing or
replacing the backing FD before interception makes later growth fail with
`EBADF` or `ESTALE`; the replacement file is not truncated. Actual allocation is
subject to memory, address, and file-size limits; exhausted backing capacity
reports `ENOMEM`. Constructor failure is cached and reported by registration
APIs, with no private fallback or automatic retry (`EFBIG` if the initial
file-size limit permits less than one page). Calls before the constructor report
`ENODEV`. Initialization, mutex, and mapping errors leave registrations
unchanged: insert returns `-1`, remove returns NULL, and clear returns -1 with
errno set. Failure to restore a temporary physical signal mask or to map enough
storage for dispatch is fatal. Static clients using the exported CMake target
retain this constructor through its linker script.

Changes are serialized with other insert/remove/clear calls, but do **not** run
in lockstep with dispatch. Across **all sharing processes**, the caller must
ensure no callback is executing and prevent dispatch, including signal delivery
and fork/clone, during changes. Removal and clear do not wait for callbacks.
These APIs are not async-signal-safe; keep callback code and state alive until
the caller establishes quiescence. Detected hook/epilogue-context changes fail
with `EDEADLK`; clear then returns -1 and leaves the list unchanged. The context
check cannot detect other active processes, threads, or callback frames.

This registration API does not change recursive syscall suppression or add
per-project FD ownership and signal-policy composition. Libraries using the
former per-type functions or extern callback variables must migrate; registering
multiple unmodified consumers is not a complete interoperability layer.

## Operating principles

These principles define the guarantees and their limits. Behavior that violates
them within the stated scope is a bug.

These guarantees apply with `OVERLAYSYS_PEDANTIC=1`. By default (unset or `0`),
the native paths and exceptions under [Pedantic mode](#pedantic-mode) apply.

1. **Application behavior.** _Intercepted operations preserve behavior unless a
   hook or policy changes it._

   In both PEDANTIC modes, syscall wrappers preserve arithmetic/direction flags
   and CPU/OS-enabled x87/MMX, SSE, AVX, and AVX-512 register state across C
   processing, including FP control state. C hooks enter with an empty x87
   stack. `rcx` and `r11` remain clobbered as allowed by the syscall ABI. The
   FP/SIMD snapshot excludes unrelated state such as PKRU so that native syscall
   effects on that state are retained.

   With `PEDANTIC=0`, supported CPUs can avoid saving an x87 component they
   report as initial. Observed x87/MMX use switches that thread to ordinary
   saves. This follows the ISA's initial-state rules: raw historical x87 opcode
   (FOP) bits in an otherwise initial component need not survive a hook.
   Arithmetic values, control/exception state, and other FP/SIMD components
   remain preserved. `PEDANTIC=1` keeps ordinary saves for this case too.

   Timing, scheduling, resource usage, patched code, and memory layout remain
   observable. `/proc`, ptrace, and seccomp reflect actual kernel state.

2. **Syscall dispatch.** _Direct nested syscalls skip user syscall hooks and
   retain essential emulation._

   Direct intercepted calls from hooks/epilogues skip user syscall hooks,
   preventing direct recursion while preserving required signal/FD/lifecycle
   emulation. Selected native operations needing no bookkeeping execute directly
   in assembly without entering C. Nonzero `forward` continues the chain and
   ultimately delegates the original operation; `0` returns that hook's
   replacement result. If a nested call already completed that operation, return
   its result with `forward = 0` to prevent duplicate execution. Auxiliary calls
   alone do not replace the original operation.

   **At the first interception depth, `forward = 0` also skips that call's
   internal emulation, even when it entered through correctly patched code.**
   There is no later reconciliation of the replacement's effects, including in
   `PEDANTIC=1`. Directly replacing a tracked state change can leave logical
   signal masks/actions, pending or signalfd/epoll state, FD aliases, or clone
   ownership inconsistent; returning the expected result is not enough. Leave
   `forward` nonzero, or perform the operation through intercepted nested calls
   that preserve its required handling before consuming the outer call. Raw
   `_overlaysys_syscall()` does not provide this protection. A rejection without
   effects or an operation needing no tracked-state handling may be replaced
   directly; the syscall name alone does not determine whether emulation is
   required.

   Keep the following syscalls on the intercepted path; raw/unpatched
   instructions bypass their bookkeeping and validation. Kernel names omit the
   `SYS_` prefix.

   | Scope           | Syscalls                                                                                             |
   | --------------- | ---------------------------------------------------------------------------------------------------- |
   | Lifecycle       | `clone`, `clone3`, `fork`, `vfork`, `exit`                                                           |
   | Signals         | `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `rt_sigtimedwait`, `rt_sigsuspend`, `sigaltstack` |
   | Signalfd I/O    | `signalfd`, `signalfd4`, `read`, `readv`                                                             |
   | Epoll           | `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`, `epoll_pwait2`            |
   | FD management   | `close`, `close_range`, `dup`, `dup2`, `dup3`, `fcntl`, `unshare`                                    |
   | Other I/O waits | `poll`, `select`, `ppoll`, `pselect6`                                                                |

   Intervention is conditional: for example, `read/readv` handle tracked
   signalfd reads, `fcntl` handles FD duplication, and `unshare` handles
   `CLONE_FILES`. Unrelated operations remain native. The pending,
   signal-context, and lifecycle restrictions below still apply. Signal hooks
   remain active; original signal handlers use application dispatch and may
   invoke syscall hooks when their inherited dispatch state permits it.

3. **Callback execution.** _Enter callbacks without internal locks and discard
   incidental errno changes._

   Hooks may perform real-FD I/O, wait, and query logical signal settings.
   Internal locks are also released before waits. Replacement errors and
   original-handler errno changes remain visible. Signal hooks stay active even
   when user syscall-hook dispatch is suppressed.

   C++ exceptions may be caught inside ordinary callbacks, but must not escape
   into OverlaySys. C++ exception handling in signal-handler context is
   unsupported.

4. **Signal dispatch.** _Manual handler calls and automatic forwarding are
   independent._

   Each intercepted arrival and eligible pending replay invokes registered
   signal hooks in order with real `siginfo`, writable `ucontext`, and shared
   `extsiginfo_t` until one consumes the signal. `extra->orig_handler` is a
   continuation for this invocation's captured action. Call it only inside the
   hook with the supplied `sig`, `info`, and `ucontext`; do not retain the
   continuation or `extra`.

   Manual calls may repeat and do not change `forward`. `inhibit_orig` describes
   automatic inhibition at hook entry: deferred/blocked, ignored, or
   default-ignore/continue. It does not prohibit manual calls; ignored and
   default-ignore/continue actions do nothing. After return, `forward` and the
   captured blocking/disposition state determine automatic delivery or pending
   publication. Set `forward = 0` to finish without either; prior manual calls
   still take effect.

5. **Pending and one-shot signals.** _Pending publication waits for hook return;
   one-shot claims resolve at dispatch._

   Unfinished records stay hidden and retain their per-signal order. Only
   forwarded standard arrivals coalesce, keeping the first `siginfo`; realtime
   records keep per-signal FIFO order. Unblocking replays through the current
   action and hook; `sigwait*` and signalfd consume eligible pending records
   without automatic handler dispatch. Installing ignore discards older records;
   clearing policies retains them. Waiting for the current hook's own decision
   cannot make progress.

   Each `SA_RESETHAND` registration is claimed once per process. Further manual
   calls in the same invocation repeat its resolved action. Deliveries that lose
   the claim use the default action without consuming a newer registration.
   Automatic forwarding after a manual one-shot dispatch also uses the default
   action.

6. **Waits and restart decisions.** _Base retries on the action that ran and the
   syscall's own rules._

   Read `extra->restartable` **after** a manual call: one-shot resolution may
   change it. It reflects the selected handler's requested `SA_RESTART`,
   independently of policy-forced kernel flags; `SIG_DFL` reports `true`. It
   neither proves handler execution nor triggers a restart. Count actual
   dispatches and apply the syscall's timeout and partial-result rules.

   Emulated signal and I/O multiplexing waits retry hook-only interruptions
   without extending timeouts; wrapped handler delivery preserves `EINTR`.
   Signalfd I/O respects wrapped handler restart decisions. Other syscalls
   remain native to avoid broader execution tracking: consumed signals may cause
   `EINTR`, and forced `SA_RESTART` may restart otherwise interruptible calls.

7. **Signal policies.** _Override kernel signal handling while preserving
   logical actions and masks._

   Process-wide `force_hook` selects `SIG_DFL` interception; `inhibit_block`
   independently overrides `SIG_IGN` and blocking. Use both to intercept
   `SIG_DFL` despite blocking. Masks remain per thread, including temporary
   masks in `sigsuspend`, `pselect`, `ppoll`, and `epoll_pwait*`. Return masks
   preserve syscall and signal-context semantics.

   `OVERLAYSYS_DEFSIGHAND` is read once during initialization: `1` forces
   `force_hook` for all eligible signals; `2` forces both policies. Later API
   calls cannot clear these bits, including with an empty set. Initialization
   exemptions and reserved signals remain excluded. When unset, each non-NULL
   API set replaces its policy and NULL preserves it. Queries return effective
   policies, including environment-forced bits.

   Inhibited signals force shared `SA_RESTART` while ignored or logically
   blocked by a tracked thread; otherwise the requested flag applies.

   Policy changes update dispositions and the caller's kernel mask immediately.
   Other threads refresh on later mask/signal paths; hooks are not guaranteed
   while their kernel masks still block delivery. Policy APIs return `-1` with
   errno on failure without logging or asserting; successful per-signal changes
   may remain. Cleanup is attempted, but a kernel-denied cleanup operation can
   prevent complete restoration.

   First-activation handler/`SIG_IGN` signal numbers stay exempt after
   disposition changes, preserving ASan/Valgrind compatibility. Their native
   handlers bypass errno/delivery bookkeeping and must preserve errno when
   interrupting hooks. Mixed native/wrapped deliveries cannot guarantee their
   exact restart behavior. `SIGKILL`, `SIGSTOP`, and libc-reserved signals are
   excluded from policies.

8. **Thread and process ownership.** _New threads inherit syscall-hook
   participation; fork resumes the copied context._

   New threads and clone children starting on a new stack inherit the creator's
   dispatch eligibility. Creation inside a hook/callback suppresses user syscall
   hooks in that child and its descendants. A fork inside a hook continues that
   hook with reentry suppressed; after return, the inherited dispatch state
   applies. Fork snapshots are serialized before callbacks. Clone/clone3 parent
   callbacks also receive errors rejected before kernel execution.

   Shared-VM children require the same thread group, shared signal dispositions,
   independent TLS, and a separate stack. Unsupported clone modes and
   intercepted `vfork` fail with `EOPNOTSUPP`. Software pending records belong
   to the receiving thread, cannot be consumed by other threads, disappear on
   its exit, and are not inherited by fork children.

   FD tracking follows descriptor-table sharing/copying within the address
   space. External changes to shared signalfd/epoll descriptions and unobserved
   FD transfers are not mirrored. `unshare(CLONE_FILES)` and
   `close_range(CLOSE_RANGE_UNSHARE)` work in synchronous code, including
   syscall hooks, but must not run in signal hooks or application signal
   handlers. This caller requirement avoids lifetime guards on ordinary FD
   lookups; it is not a runtime rejection.

9. **Host requirements.** _The host must permit internal syscalls and required
   `/proc` access._

   User-memory copies require `process_vm_writev` or
   `pipe2`/`read`/`write`/`close`. Retained ordinary epoll events require
   readable `/proc/thread-self/fdinfo`. Nonzero timeouts require a working
   monotonic clock via vDSO or `clock_gettime`. OverlaySys does not bypass
   kernel restrictions.

## Pedantic mode

`OVERLAYSYS_PEDANTIC` accepts only `0` or `1`: unset or `0` enables optimized
native paths; explicit `1` uses the original signal/FD emulation. It is read
once during initialization and fixed for the process lifetime; the C API is
identical. Both modes retain signal delivery/hooks, original-handler
continuation and notifications, fault fixup, logical actions/masks, direct
signal consumers, and clone ownership, including UserNet handler accounting and
libacceldev's blocked/ignored SIGSEGV interception.

With `0`, CPU-reported initial x87 state also uses the optimization described
under application behavior above; only its raw FOP history is outside the
preservation guarantee. This is independent of the native-wait limits below.

With `0`, native `ppoll`, `pselect6`, and epoll waits use kernel timeout,
pointer-validation, and interruption rules. Eligibility requires no software
pending records, active signalfds, retained epoll events, or inhibition beyond
SIGSEGV/SIGBUS:

- Without a temporary mask, fault-only inhibition is allowed because the
  caller's physical mask is already filtered. A `pselect6` argument structure
  whose inner mask pointer is NULL also takes this path after a safe snapshot.
- With a temporary mask, `ppoll` and `pselect6` also allow fault-only
  inhibition: they safely snapshot the mask, remove inhibited fault bits from
  the kernel mask, and retain a live frame to distinguish delivery and return
  masks. Other temporary-mask waits require no inhibition. No wrapped action may
  need full emulation: original application handlers require it; default/ignored
  SIGSEGV/SIGBUS hooks count as fault observers. Stale action bits may
  conservatively keep a wait emulated.
- Epolls created while signalfds or nonfault inhibition exist stay tracked,
  including their aliases and decoding after signalfds close or policies change.
  Otherwise they use native registrations/user data; kernel ET, ONESHOT, alias,
  and shared-description semantics remain intact. Fault-only inhibition alone
  does not select tracking.

Native paths have these limits:

- Hook-consumed signals may expose `EINTR` without an emulated retry; forwarded
  application handlers still run and are recorded. Output faults use kernel
  behavior without a separately retained epoll event suffix.
- Native epolls do not synthesize software-pending readiness added later through
  signalfd or nested tracked epolls. Configure the relevant nonfault inhibition
  or create signalfds before creating such epolls, or use `1`.
- Coordinate disposition/inhibition and virtual-readiness changes with in-flight
  native waits: they are not converted when another thread changes these
  settings. Mask edits by native exempt handlers racing with wait entry also
  lack the full logical-mask guarantee. Ordinary kernel FD readiness changes
  still work.
- For default/ignored SIGSEGV/SIGBUS, native temporary-mask waits do not
  guarantee exact pending, forwarding, or replay order for asynchronously
  injected signals, or hide hook-only interruptions. Eligible genuine
  protected-memory faults remain intercepted, including with fault-only
  inhibition through a temporary mask. Custom original fault handlers retain the
  full temporary-mask path.

Not every wait becomes native. Use `1` when full pending/readiness and
interruption guarantees are required.

## Building the API reference

The public API is documented in [include/overlaysys.h](include/overlaysys.h).
Enable Doxygen generation to build the HTML reference alongside the library:

```sh
cmake -S . -B build -DOVERLAYSYS_BUILD_DOCS=ON
cmake --build build
```

Open `build/docs/html/index.html`. The `overlaysys-docs` target can also be
built separately. Documentation warnings fail the documentation build. The
option is off by default, so ordinary library builds do not require Doxygen.
