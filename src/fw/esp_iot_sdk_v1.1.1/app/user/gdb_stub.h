#ifndef __GDB_STUB_H__
#define __GDB_STUB_H__

#include "user_config.h"

#ifdef GDB_STUB
/**
 * Install exception handlers.
 * Not compatible with debug_esp.
 */
void gdb_stub_init();
/**
 * Break and enter the debugger.
 * Calling this allow the debugger to attach.
 * TODO make this work
 */
#define gdb_stub_break() __asm__ __volatile__("break 1, 1")
#else
#define gdb_stub_init()
#define gdb_stub_break()
#endif

#endif
