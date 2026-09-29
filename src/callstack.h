#pragma once

#include <stdatomic.h>
#include <stdint.h>

#include <stdbool.h>

#include <elfutils/libdw.h>

/* x86-64 DWARF register numbers, including the return instruction pointer. */
enum { CALLSTACK_REGISTERS = 17 };

struct callstack_expression {
  Dwarf_Op *ops;
  size_t count;
};

enum callstack_rule_kind {
  CALLSTACK_UNDEFINED,
  CALLSTACK_SAME,
  CALLSTACK_EXPRESSION
};

struct callstack_rule {
  enum callstack_rule_kind kind;
  struct callstack_expression expression;
};

struct callstack_row {
  uintptr_t start;
  uintptr_t end;
  unsigned return_register;
  bool signal;
  struct callstack_expression cfa;
  struct callstack_rule registers[CALLSTACK_REGISTERS];
};

struct callstack_function {
  uintptr_t start;
  uintptr_t end;
};

/* Published modules, their loader references, and copied rules are immutable
 * and retained until process exit. Query code never enters the loader. */
struct callstack_module {
  uintptr_t start;
  uintptr_t end;
  uintptr_t bias;
  const void *identity;
  void *handle;
  struct callstack_function *functions;
  size_t function_count;
  struct callstack_row *rows;
  size_t row_count;
  struct callstack_module *next;
};

extern __attribute__((
    visibility("hidden"))) _Atomic(struct callstack_module *) callstack_modules;
extern __attribute__((visibility("hidden"))) _Atomic bool callstack_ready;

/* Captured by callstack.S at the public entry, in DWARF register order. */
struct callstack_registers {
  uintptr_t values[CALLSTACK_REGISTERS];
};

__attribute__((visibility("hidden"))) int
callstack_check(const void *restrict func_ptr, bool *restrict on_callstack,
                const struct callstack_registers *restrict registers);

/* Fixed-wrapper return PC: its preserved RBX points at runtime_ctx. */
extern __attribute__((visibility("hidden")))
const unsigned char callstack_intercept_return[];
