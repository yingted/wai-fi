#ifdef GDB_STUB
#include "user_config.h"
#include "xtensa/xtruntime-frames.h"
#include "xtensa/corebits.h"
#include "gdb_stub.h"
#include <stdbool.h>
#include <stddef.h>

// Template function macros
#define IF_0(then, else) else
#define IF_1(then, else) then
#define IF(cond, then, else) IF_ ## cond(then, else)

struct GdbRegister {
    size_t val;
    bool valid;
};

struct GdbFrame {
#define REG_XTENSA_reg32(x, have) IF(have, struct GdbRegister x;, )
#include "reg-xtensa.h"
#undef REG_XTENSA_reg32
};

static struct GdbFrame regs;

/**
 * Exception handler called from xtensa proprietary code.
 * The code does the equivalent of:
 * wsr.excsave1 a0
 * addmi a1, a1, -256
 * ... save registers
 * jump to exception_table[a2]
 */
ICACHE_FLASH_ATTR
static void exception_handler(UserFrame *frame) {
    size_t excvaddr, litbase;
    asm("rsr.excvaddr %0":"=r"(excvaddr));
    asm("rsr.litbase %0":"=r"(litbase));
#define REGISTER_ARG(x, arg) do { \
    regs.x.val = arg; \
    regs.x.valid = true; \
} while (0)
#define REGISTER(x) REGISTER_ARG(x, frame->x)
    REGISTER(pc);
    REGISTER(ps);
    REGISTER(sar);
    REGISTER(a0);
    REGISTER_ARG(a1, ((size_t)frame) + 0x100);
    REGISTER(a2);
    REGISTER(a3);
    REGISTER(a4);
    REGISTER(a5);
    REGISTER(a6);
    REGISTER(a7);
    REGISTER(a8);
    REGISTER(a9);
    REGISTER(a10);
    REGISTER(a11);
    REGISTER(a12);
    REGISTER(a13);
    REGISTER(a14);
    REGISTER(a15);
    REGISTER_ARG(litbase, litbase);
#undef REGISTER
#undef REGISTER_ARG

    user_dprintf("vpri=%d exccause=%d excvaddr=%p", frame->vpri, frame->exccause, (void *)excvaddr);
    os_memset(&regs, 0, sizeof(regs));
}

ICACHE_FLASH_ATTR
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

ICACHE_FLASH_ATTR
void gdb_stub_break() {
    asm("break 1,1"); // unhandled level 1 user exception
    gdb_stub_DebugExceptionVector();
}

__asm__("\
    .section .DebugExceptionVector.text\n\
    .global gdb_stub_DebugExceptionVector \n\
    gdb_stub_DebugExceptionVector:\n\
        waiti 2\n\
        j gdb_stub_DebugExceptionVector\n\
");
#endif
