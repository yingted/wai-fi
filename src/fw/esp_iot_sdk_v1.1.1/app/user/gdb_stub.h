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
 */
void gdb_stub_break();
#else
#define gdb_stub_init()
#define gdb_stub_break()
#endif

#endif
