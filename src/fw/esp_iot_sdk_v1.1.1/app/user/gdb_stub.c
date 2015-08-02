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

ICACHE_FLASH_ATTR
void real_putc1(char c) {
    XXX
}

ICACHE_FLASH_ATTR
void gdb_putc1(char c) {
    XXX
}

ICACHE_FLASH_ATTR
void gdb_restore_state() {
    ets_install_putc1(real_putc1);
    for (;;); // too bad
}

bool gdb_read_err;
uint8_t gdb_read_cksum;

ICACHE_FLASH_ATTR
char gdb_read_char() {
    if (gdb_read_err) {
        return 0;
    }
    char ch = XXX;
    if (ch == '#') {
        gdb_read_err = true;
    } else {
        gdb_read_cksum += ch;
    }
    return ch;
}

uint8_t gdb_write_cksum;

ICACHE_FLASH_ATTR
void gdb_write_packet(char *buf) {
    for (; *buf; ++buf) {
        gdb_write_cksum += *buf;
        real_putc1(*buf);
    }
}

ICACHE_FLASH_ATTR
void gdb_write_byte(uint8_t b) {
    char buf[3];
    os_sprintf(buf, "%02x", b);
    gdb_write_packet(buf);
}

ICACHE_FLASH_ATTR
void gdb_flush_packet() {
    real_putc1('#');
    gdb_write_byte(gdb_write_cksum);
}

ICACHE_FLASH_ATTR
void gdb_install_io() {
    ets_install_putc1(gdb_put1c);
}

ICACHE_FLASH_ATTR
uint8_t gdb_read_byte() {
    uint8_t a = gdb_read_char() & 0x4f;
    a = (a & 0xf) + 9 * (a >> 6);
    uint8_t b = gdb_read_char() & 0x4f;
    b = (b & 0xf) + 9 * (b >> 6);
    return (a >> 4) | b;
}

ICACHE_FLASH_ATTR
bool gdb_read_to_cksum() {
    while (!gdb_read_err) {
        gdb_read_char();
    }
    bool ret = gdb_read_byte() == gdb_read_cksum;
    gdb_write_packet(ret ? "+" : "-");
    return ret;
}

ICACHE_FLASH_ATTR
void gdb_download(size_t addr, size_t len) {
    uint8_t buf[len];
    size_t i;
    for (i = 0; i != len; ++i) {
        buf[i] = gdb_read_byte();
    }
    if (gdb_read_to_cksum()) {
        os_memcpy(addr, buf, len);
    }
}

ICACHE_FLASH_ATTR
size_t gdb_read_int() {
    size_t ret = 0;
    ret = (ret << 8) | gdb_read_byte();
    ret = (ret << 8) | gdb_read_byte();
    ret = (ret << 8) | gdb_read_byte();
    ret = (ret << 8) | gdb_read_byte();
    return ret;
}

ICACHE_FLASH_ATTR
void gdb_attach() {
    bool has_breakpoint = false;
    size_t breakpoint_addr;
    register size_t saved_ps asm("a2");
    asm("rsil %0, 15":"+r"(saved_ps));
    gdb_install_io();
    gdb_write_packet("vStopped");
    for (;;) {
        gdb_read_err = false;
        char dollar = gdb_read_char();
        if (gdb_read_err || dollar != '$') {
            if (gdb_read_to_cksum()) {
                gdb_write_packet("");
            }
            break;
        }
        gdb_read_cksum = 0;
        gdb_write_packet("$");
        gdb_write_cksum = 0;
        gdb_read_to_cksum();
        char cmd = gdb_read_char();
        size_t addr, len;
        switch (cmd) {
            case '?':
                gdb_write_packet("S09");
                break;
            case 'D':
            case 'c':
                size_t pc = gdb_read_int();
                if (gdb_read_err) {
                    pc = regs.pc;
                }
                if (!gdb_read_to_cksum()) {
                    break;
                }
                regs.pc = pc;
                gdb_write_packet("OK");
                goto cont;
            // read addr, length
            case 'm':
                addr = gdb_read_int();
                len = gdb_read_int();
                if (!gdb_read_to_cksum()) {
                    break;
                }
                for (; len; ++addr, --len) {
                    gdb_write_byte(gdb_read_addr(addr));
                }
                break;
            // write addr, length, binary
            case 'M':
                addr = gdb_read_int();
                len = gdb_read_int();
                gdb_download(addr, len);
                break;
            // read all registers
            case 'g':
                if (!gdb_read_to_cksum()) {
                    break;
                }
                {
                    struct GdbRegister *begin = (struct GdbRegister *)&regs;
                    struct GdbRegister *end = (struct GdbRegister *)((char *)&regs + sizeof(regs));
                    for (; end - begin; ++begin) {
                        char buf[9];
                        os_memcpy(buf, "xxxxxxxx", sizeof(buf));
                        if (begin->valid) {
                            os_sprintf(buf, "%08x", begin->val);
                        }
                        gdb_send_packet(buf);
                    }
                }
                break;
            case 'z':
            case 'Z': {
                char kind = gdb_read_char();
                addr;
                if (kind == 1) {
                    addr = gdb_read_int();
                    gdb_read_int();
                }
                if (!gdb_read_to_cksum()) {
                    break;
                }
                if (kind != 1) {
                    gdb_write_packet("");
                    break;
                }
                switch (cmd) {
                    case 'z':
                        if (!has_breakpoint) {
                            break;
                        }
                        break;
                    case 'Z':
                        if (has_breakpoint) {
                            if (addr == breakpoint_addr) {
                                break;
                            }
                            gdb_write_packet("E00");
                            break;
                        }
                        __asm__("wsr.ibreaka1 %0"::"r"(addr));
                        __asm__("wsr.ibreakenable %0"::"r"(1));
                        break;
                }
                gdb_write_packet("OK");
                break;
            }
            case 'k':
                system_restart();
                break;
            // discard silently
            case 'F':
                gdb_read_to_cksum();
                break;
            // qXfer:memory-map:read
            case 'q':
            // unsupported
            default:
                if (gdb_read_to_cksum()) {
                    gdb_write_packet("");
                }
                break;
        }
        gdb_flush_packet();
    }
cont:
    asm("wsr.ps %0"::"r"(saved_ps));
    gdb_restore_state();
}

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
    os_memset(&regs, 0, sizeof(regs));
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

    user_dprintf("vpri=%d exccause=%d excvaddr=%p pc=%p", frame->vpri, frame->exccause, (void *)excvaddr, (void *)frame->pc);
    gdb_attach();
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

__asm__("\
    .section .DebugExceptionVector.text\n\
    .global gdb_stub_DebugExceptionVector \n\
    gdb_stub_DebugExceptionVector:\n\
        j _UserExceptionVector\n\
");
#endif
