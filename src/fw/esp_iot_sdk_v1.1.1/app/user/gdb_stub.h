#ifndef __GDB_STUB_H__
#define __GDB_STUB_H__

#include <user_config.h>

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
#define gdb_stub_break() __asm__ __volatile__("break 1, 1")
#define gdb_stub_break_force() do { \
    size_t ps; \
    __asm__ __volatile__("\
        rsil %0, 0\n\
        isync\n\
        break 1, 1\n\
        wsr %0, ps\n\
        isync\n\
    "::"r"(ps)); \
} while (0)
#else
#define gdb_stub_init()
#define gdb_stub_break()
#define gdb_stub_break_force()
#endif

#endif
