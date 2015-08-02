#include "user_config.h"
#include "gdb_stub.h"
#ifdef GDB_STUB
#include "xtensa/corebits.h"
#include "xtensa/xtruntime-frames.h"

// Template function macros
#define EXPAND_CALL(macro, arg) macro(arg)
#define IF_0(then, else) else
#define IF_1(then, else) then
#define IF(cond, then, else) EXPAND_CALL(IF_ ## cond, then, else)

static void exception_handler(UserFrame *frame) {
    size_t exccause, excvaddr, litbase;
    asm("rsr.exccause %0":"=r"(exccause));
    asm("rsr.excvaddr %0":"=r"(excvaddr));
    asm("rsr.litbase %0":"=r"(litbase));
    size_t a1 = ((size_t)&frame) + 0x100;
#define SHOW_LOCAL(x) user_dprintf(#x ": %p", (void *)(x))
#define SHOW(x) SHOW_LOCAL(frame->x)
    SHOW(pc);
    SHOW(ps);
    SHOW(sar);
    SHOW(vpri);
    SHOW(a0);
    SHOW_LOCAL(a1);
    SHOW(a2);
    SHOW(a3);
    SHOW(a4);
    SHOW(a5);
    SHOW(a6);
    SHOW(a7);
    SHOW(a8);
    SHOW(a9);
    SHOW(a10);
    SHOW(a11);
    SHOW(a12);
    SHOW(a13);
    SHOW(a14);
    SHOW(a15);
    SHOW(exccause);
    SHOW_LOCAL(exccause);
    SHOW_LOCAL(excvaddr);
}

void gdb_stub_init() {
    const static uint8_t exceptions[] = {
        EXCCAUSE_ILLEGAL,
        EXCCAUSE_INSTR_ERROR,
        EXCCAUSE_LOAD_STORE_ERROR,
        EXCCAUSE_DIVIDE_BY_ZERO,
        EXCCAUSE_UNALIGNED,
        EXCCAUSE_INSTR_PROHIBITED,
        EXCCAUSE_LOAD_PROHIBITED,
        EXCCAUSE_STORE_PROHIBITED,
    };
    size_t i;
    for (i = 0; i != sizeof(exceptions); ++i) {
        _xtos_set_exception_handler(exceptions[i], exception_handler);
    }
}

void gdb_stub_break() {
}
#endif
