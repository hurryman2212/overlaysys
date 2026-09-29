#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include <sys/syscall.h>
#include <sys/uio.h>

#include <dwarf.h>

#include "callstack.h"

#include "patcher/patcher.h"
#include "patcher/x86/runtime.h"

/* Bound both stack use and work for damaged or unusual unwind programs. */
enum {
  CALLSTACK_MAX_FRAMES = 256,
  CALLSTACK_MAX_OPS = 256,
  CALLSTACK_MAX_STEPS = 4096
};

static_assert(ATOMIC_POINTER_LOCK_FREE == 2 && ATOMIC_BOOL_LOCK_FREE == 2,
              "call-stack queries require lock-free metadata publication");

struct callstack_state {
  uintptr_t values[CALLSTACK_REGISTERS];
  uint32_t valid;
};

static int callstack_read(long pid, uintptr_t address, void *data,
                          size_t size) {
  if (!address || size > UINTPTR_MAX - address)
    return EFAULT;
  struct iovec local = {.iov_base = data, .iov_len = size};
  struct iovec remote = {.iov_base = (void *)address, .iov_len = size};
  const long result = util_syscall_no_intercept(SYS_process_vm_readv, pid,
                                                &local, 1UL, &remote, 1UL, 0UL);
  if (result < 0)
    return (int)-result;
  return (size_t)result == size ? 0 : EFAULT;
}

static const struct callstack_module *
callstack_module_at(const struct callstack_module *modules, uintptr_t pc) {
  for (const struct callstack_module *module = modules; module;
       module = module->next)
    if (pc >= module->start && pc < module->end)
      return module;
  return NULL;
}

static const struct callstack_row *
callstack_row_at(const struct callstack_module *module, uintptr_t pc) {
  size_t first = 0, end = module->row_count;
  while (first < end) {
    const size_t middle = first + (end - first) / 2;
    if (module->rows[middle].start <= pc)
      first = middle + 1;
    else
      end = middle;
  }
  if (!first || pc >= module->rows[first - 1].end)
    return NULL;
  return module->rows + first - 1;
}

/* libdw represents CFI locations by prepending call_frame_cfa; value rules
 * end in stack_value. CFA rules themselves always compute a value. */
static int callstack_evaluate(const struct callstack_expression *expression,
                              const struct callstack_state *state,
                              uintptr_t bias, long pid, bool have_cfa,
                              uintptr_t cfa, uintptr_t *value) {
  if (!expression->count || !expression->ops)
    return ENODATA;
  if (expression->count > CALLSTACK_MAX_OPS)
    return EOVERFLOW;
  uintptr_t stack[CALLSTACK_MAX_OPS];
  size_t depth = 0, pc = 0;
  unsigned steps = 0;
  bool location = have_cfa;
  while (pc < expression->count) {
    if (++steps > CALLSTACK_MAX_STEPS)
      return EOVERFLOW;
    const Dwarf_Op *op = expression->ops + pc++;
    uintptr_t pushed = 0;
    if (op->atom >= DW_OP_lit0 && op->atom <= DW_OP_lit31) {
      pushed = op->atom - DW_OP_lit0;
    } else if ((op->atom >= DW_OP_reg0 && op->atom <= DW_OP_reg31) ||
               (op->atom >= DW_OP_breg0 && op->atom <= DW_OP_breg31) ||
               op->atom == DW_OP_regx || op->atom == DW_OP_bregx) {
      const bool base = (op->atom >= DW_OP_breg0 && op->atom <= DW_OP_breg31) ||
                        op->atom == DW_OP_bregx;
      const uint64_t reg = op->atom == DW_OP_regx || op->atom == DW_OP_bregx
                               ? op->number
                               : op->atom - (base ? DW_OP_breg0 : DW_OP_reg0);
      if (reg >= CALLSTACK_REGISTERS)
        return EOPNOTSUPP;
      if (!(state->valid & (1U << reg)))
        return ENODATA;
      pushed = state->values[reg];
      if (base) {
        pushed += op->atom == DW_OP_bregx ? op->number2 : op->number;
      } else {
        /* A register location denotes its value, not a memory address. */
        if (pc < expression->count &&
            (pc + 1 != expression->count ||
             expression->ops[pc].atom != DW_OP_stack_value))
          return EOPNOTSUPP;
        location = false;
      }
    } else {
      switch (op->atom) {
      case DW_OP_addr:
        pushed = op->number + bias;
        break;
      case DW_OP_const1u:
      case DW_OP_const1s:
      case DW_OP_const2u:
      case DW_OP_const2s:
      case DW_OP_const4u:
      case DW_OP_const4s:
      case DW_OP_const8u:
      case DW_OP_const8s:
      case DW_OP_constu:
      case DW_OP_consts:
        pushed = op->number;
        break;
      case DW_OP_call_frame_cfa:
        if (!have_cfa)
          return EOPNOTSUPP;
        pushed = cfa;
        location = true;
        break;
      case DW_OP_stack_value:
        if (pc != expression->count)
          return EOPNOTSUPP;
        if (!depth)
          return EINVAL;
        location = false;
        continue;
      case DW_OP_dup:
      case DW_OP_over:
      case DW_OP_pick: {
        const uintptr_t offset = op->atom == DW_OP_dup    ? 0
                                 : op->atom == DW_OP_over ? 1
                                                          : op->number;
        if (offset >= depth)
          return EINVAL;
        pushed = stack[depth - 1 - offset];
        break;
      }
      case DW_OP_drop:
        if (!depth)
          return EINVAL;
        --depth;
        continue;
      case DW_OP_swap:
      case DW_OP_rot: {
        const size_t count = op->atom == DW_OP_swap ? 2 : 3;
        if (depth < count)
          return EINVAL;
        const uintptr_t top = stack[depth - 1];
        stack[depth - 1] = stack[depth - 2];
        if (count == 3)
          stack[depth - 2] = stack[depth - 3];
        stack[depth - count] = top;
        continue;
      }
      case DW_OP_deref:
      case DW_OP_deref_size: {
        if (!depth)
          return EINVAL;
        const size_t size =
            op->atom == DW_OP_deref ? sizeof(uintptr_t) : op->number;
        if (!size || size > sizeof(uintptr_t))
          return EOPNOTSUPP;
        uintptr_t result = 0;
        const int err = callstack_read(pid, stack[depth - 1], &result, size);
        if (err)
          return err;
        stack[depth - 1] = result;
        continue;
      }
      case DW_OP_abs:
      case DW_OP_neg:
      case DW_OP_not:
      case DW_OP_plus_uconst:
        if (!depth)
          return EINVAL;
        if (op->atom == DW_OP_not)
          stack[depth - 1] = ~stack[depth - 1];
        else if (op->atom == DW_OP_plus_uconst)
          stack[depth - 1] += op->number;
        else if (op->atom == DW_OP_neg || (intptr_t)stack[depth - 1] < 0)
          stack[depth - 1] = -stack[depth - 1];
        continue;
      case DW_OP_and:
      case DW_OP_div:
      case DW_OP_minus:
      case DW_OP_mod:
      case DW_OP_mul:
      case DW_OP_or:
      case DW_OP_plus:
      case DW_OP_shl:
      case DW_OP_shr:
      case DW_OP_shra:
      case DW_OP_xor:
      case DW_OP_eq:
      case DW_OP_ge:
      case DW_OP_gt:
      case DW_OP_le:
      case DW_OP_lt:
      case DW_OP_ne: {
        if (depth < 2)
          return EINVAL;
        const uintptr_t right = stack[--depth], left = stack[depth - 1];
        switch (op->atom) {
        case DW_OP_and:
          pushed = left & right;
          break;
        case DW_OP_div:
          if (!right ||
              (left == (uintptr_t)INTPTR_MIN && right == (uintptr_t)-1))
            return EINVAL;
          pushed = (intptr_t)left / (intptr_t)right;
          break;
        case DW_OP_minus:
          pushed = left - right;
          break;
        case DW_OP_mod:
          if (!right)
            return EINVAL;
          pushed = left % right;
          break;
        case DW_OP_mul:
          pushed = left * right;
          break;
        case DW_OP_or:
          pushed = left | right;
          break;
        case DW_OP_plus:
          pushed = left + right;
          break;
        case DW_OP_shl:
        case DW_OP_shr:
        case DW_OP_shra:
          if (right >= sizeof(uintptr_t) * CHAR_BIT)
            return EINVAL;
          pushed = op->atom == DW_OP_shl ? left << right
                   : op->atom == DW_OP_shr
                       ? left >> right
                       : (uintptr_t)((intptr_t)left >> right);
          break;
        case DW_OP_xor:
          pushed = left ^ right;
          break;
        case DW_OP_eq:
          pushed = left == right;
          break;
        case DW_OP_ge:
          pushed = (intptr_t)left >= (intptr_t)right;
          break;
        case DW_OP_gt:
          pushed = (intptr_t)left > (intptr_t)right;
          break;
        case DW_OP_le:
          pushed = (intptr_t)left <= (intptr_t)right;
          break;
        case DW_OP_lt:
          pushed = (intptr_t)left < (intptr_t)right;
          break;
        default:
          pushed = left != right;
          break;
        }
        stack[depth - 1] = pushed;
        continue;
      }
      case DW_OP_bra:
      case DW_OP_skip: {
        if (op->atom == DW_OP_bra) {
          if (!depth)
            return EINVAL;
          if (!stack[--depth])
            continue;
        }
        /* Branch operands are signed 16-bit offsets from the next opcode. */
        const __int128 offset = (__int128)op->offset + 3 + (int16_t)op->number;
        if (offset < 0 || offset > UINT64_MAX)
          return EINVAL;
        size_t target = 0;
        while (target < expression->count &&
               expression->ops[target].offset != (uint64_t)offset)
          ++target;
        if (target == expression->count)
          return EINVAL;
        pc = target;
        continue;
      }
      case DW_OP_nop:
        continue;
      default:
        return EOPNOTSUPP;
      }
    }
    if (depth == CALLSTACK_MAX_OPS)
      return EOVERFLOW;
    stack[depth++] = pushed;
  }
  if (!depth)
    return EINVAL;
  *value = stack[depth - 1];
  return have_cfa && location
             ? callstack_read(pid, *value, value, sizeof(*value))
             : 0;
}

/* Generated code has no ELF CFI. The fixed wrapper preserves a pointer to its
 * saved register frame in RBX, which ordinary CFI restores before this bridge.
 */
static int callstack_intercept(struct callstack_state *state, long pid) {
  if ((state->valid & ((1U << 3) | (1U << 7))) != ((1U << 3) | (1U << 7)))
    return ENODATA;
  const uintptr_t address = state->values[3];
  if ((address & 15) || state->values[7] > address)
    return EINVAL;
  struct runtime_ctx context;
  int err = callstack_read(pid, address, &context, sizeof(context));
  if (err)
    return err;
  const uintptr_t rsp = (uintptr_t)context.rsp;
  if (rsp < 0x138 || ((rsp - 0x88) & ~(uintptr_t)15) - 0xb0 != address ||
      !context.rip)
    return EINVAL;
  uintptr_t syscall_pc;
  err = callstack_read(pid, (uintptr_t)context.patch_desc, &syscall_pc,
                       sizeof(syscall_pc));
  if (err)
    return err;
  if (syscall_pc != (uintptr_t)context.rip)
    return EINVAL;
  state->values[0] = context.rax;
  state->values[1] = context.rdx;
  state->values[3] = context.rbx;
  state->values[4] = context.rsi;
  state->values[5] = context.rdi;
  state->values[6] = context.rbp;
  state->values[7] = rsp;
  state->values[8] = context.r8;
  state->values[9] = context.r9;
  state->values[10] = context.r10;
  state->values[12] = context.r12;
  state->values[13] = context.r13;
  state->values[14] = context.r14;
  state->values[15] = context.r15;
  state->values[16] = context.rip;
  state->valid = ((1U << CALLSTACK_REGISTERS) - 1) & ~((1U << 2) | (1U << 11));
  return 0;
}

int callstack_check(const void *restrict func_ptr, bool *restrict on_callstack,
                    const struct callstack_registers *restrict registers) {
  int err = EINVAL;
  if (!func_ptr || !on_callstack || !registers)
    goto fail;
  err = ENODATA;
  if (!atomic_load_explicit(&callstack_ready, memory_order_acquire))
    goto fail;
  const struct callstack_module *modules =
      atomic_load_explicit(&callstack_modules, memory_order_acquire);
  const uintptr_t target = (uintptr_t)func_ptr;
  const struct callstack_module *module = callstack_module_at(modules, target);
  if (!module)
    goto fail;
  size_t first = 0, end = module->function_count;
  while (first < end) {
    const size_t middle = first + (end - first) / 2;
    if (module->functions[middle].start < target)
      first = middle + 1;
    else
      end = middle;
  }
  if (first == module->function_count ||
      module->functions[first].start != target ||
      module->functions[first].end <= target)
    goto fail;
  const uintptr_t target_end = module->functions[first].end;
  const long pid = util_syscall_no_intercept(SYS_getpid);
  if (pid < 0) {
    err = (int)-pid;
    goto fail;
  }
  struct callstack_state state;
  /* Volatile stores keep these fixed local copies independent of libc. */
  for (unsigned reg = 0; reg < CALLSTACK_REGISTERS; ++reg)
    ((volatile uintptr_t *)state.values)[reg] = registers->values[reg];
  state.valid = (1U << CALLSTACK_REGISTERS) - 1;
  uintptr_t seen_pc[CALLSTACK_MAX_FRAMES], seen_sp[CALLSTACK_MAX_FRAMES];
  bool exact = false;
  for (unsigned frame = 0; frame < CALLSTACK_MAX_FRAMES; ++frame) {
    if (!(state.valid & (1U << 16))) {
      err = ENODATA;
      goto fail;
    }
    const uintptr_t raw_pc = state.values[16];
    if (!raw_pc) {
      *on_callstack = false;
      return 0;
    }
    const uintptr_t pc = raw_pc - !exact;
    if (pc >= target && pc < target_end) {
      *on_callstack = true;
      return 0;
    }
    if (!(state.valid & (1U << 7))) {
      err = ENODATA;
      goto fail;
    }
    for (unsigned previous = 0; previous < frame; ++previous)
      if (seen_pc[previous] == raw_pc && seen_sp[previous] == state.values[7]) {
        err = ELOOP;
        goto fail;
      }
    seen_pc[frame] = raw_pc;
    seen_sp[frame] = state.values[7];
    if (raw_pc == (uintptr_t)callstack_intercept_return) {
      err = callstack_intercept(&state, pid);
      if (err)
        goto fail;
      module = callstack_module_at(modules, state.values[16]);
      if (!module || !callstack_row_at(module, state.values[16])) {
        err = ENODATA;
        goto fail;
      }
      exact = true;
      continue;
    }
    module = callstack_module_at(modules, pc);
    const struct callstack_row *row =
        module ? callstack_row_at(module, pc) : NULL;
    if (!row) {
      err = ENODATA;
      goto fail;
    }
    if (row->return_register >= CALLSTACK_REGISTERS) {
      err = EOPNOTSUPP;
      goto fail;
    }
    if (row->registers[row->return_register].kind == CALLSTACK_UNDEFINED) {
      *on_callstack = false;
      return 0;
    }
    uintptr_t cfa;
    err = callstack_evaluate(&row->cfa, &state, module->bias, pid, false, 0,
                             &cfa);
    if (err)
      goto fail;
    const unsigned return_register = row->return_register;
    const struct callstack_rule *return_rule = row->registers + return_register;
    uintptr_t return_pc;
    if (return_register == 7 && return_rule->kind != CALLSTACK_EXPRESSION) {
      return_pc = cfa;
    } else if (return_rule->kind == CALLSTACK_SAME) {
      if (!(state.valid & (1U << return_register))) {
        err = ENODATA;
        goto fail;
      }
      return_pc = state.values[return_register];
    } else if (return_rule->kind == CALLSTACK_EXPRESSION) {
      err = callstack_evaluate(&return_rule->expression, &state, module->bias,
                               pid, true, cfa, &return_pc);
      if (err)
        goto fail;
    } else {
      err = EINVAL;
      goto fail;
    }
    if (!return_pc) {
      *on_callstack = false;
      return 0;
    }
    struct callstack_state next;
    next.values[return_register] = return_pc;
    next.valid = 1U << return_register;
    for (unsigned reg = 0; reg < CALLSTACK_REGISTERS; ++reg) {
      if (reg == return_register)
        continue;
      const struct callstack_rule *rule = row->registers + reg;
      if (reg == 7 && rule->kind != CALLSTACK_EXPRESSION) {
        /* x86-64's caller stack pointer is the CFA unless CFI overrides it. */
        ((volatile uintptr_t *)next.values)[reg] = cfa;
      } else if (rule->kind == CALLSTACK_UNDEFINED) {
        continue;
      } else if (rule->kind == CALLSTACK_SAME) {
        if (!(state.valid & (1U << reg)))
          continue;
        ((volatile uintptr_t *)next.values)[reg] = state.values[reg];
      } else if (rule->kind == CALLSTACK_EXPRESSION) {
        uintptr_t value;
        err = callstack_evaluate(&rule->expression, &state, module->bias, pid,
                                 true, cfa, &value);
        if (err)
          goto fail;
        ((volatile uintptr_t *)next.values)[reg] = value;
      } else {
        err = EINVAL;
        goto fail;
      }
      next.valid |= 1U << reg;
    }
    next.values[16] = return_pc;
    next.valid |= 1U << 16;
    for (unsigned reg = 0; reg < CALLSTACK_REGISTERS; ++reg)
      if (next.valid & (1U << reg))
        ((volatile uintptr_t *)state.values)[reg] = next.values[reg];
    state.valid = next.valid;
    exact = row->signal;
  }
  err = EOVERFLOW;
fail:
  errno = err;
  return -1;
}
