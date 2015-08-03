#ifdef GDB_STUB
#include "user_config.h"
#include "xtensa/xtruntime-frames.h"
#include "xtensa/corebits.h"
#include "espressif/esp8266/uart_register.h"
#include "gdb_stub.h"
#include "eagle_soc.h"
#include <stdbool.h>
#include <stddef.h>

void gdb_stub_DebugExceptionVector();

// Template function macros
#define IF_0(then, else) else
#define IF_1(then, else) then
#define IF(cond, then, else) IF_ ## cond(then, else)

struct GdbRegister {
    size_t value;
    bool valid;
};

struct GdbFrame {
#define REG_XTENSA_reg32(x, have) IF(have, struct GdbRegister x;, )
#include "reg-xtensa.h"
#undef REG_XTENSA_reg32
};

static struct GdbFrame regs;

#define GDB_UART 0

ICACHE_FLASH_ATTR
void real_putc1(char c) {
    for (;;) {
        size_t fifo_cnt = (((size_t)READ_PERI_REG(UART_STATUS(GDB_UART))) >> UART_TXFIFO_CNT_S) & UART_TXFIFO_CNT;
        if (fifo_cnt < 126) {
            break;
        }
        // busy loop
    }
    WRITE_PERI_REG(UART_FIFO(GDB_UART), c);
}

ICACHE_FLASH_ATTR
char real_getc1() {
    for (;;) {
        size_t status = READ_PERI_REG(UART_INT_ST(GDB_UART));
        // if (status & UART_FRM_ERR_INT_ST) ...
        if (status & (UART_RXFIFO_FULL_INT_ST | UART_RXFIFO_TOUT_INT_ST)) {
            size_t queued = (READ_PERI_REG(UART_STATUS(GDB_UART)) >> UART_RXFIFO_CNT_S) & UART_RXFIFO_CNT;
            if (queued) {
                char ch = (READ_PERI_REG(UART_FIFO(GDB_UART)) >> UART_RXFIFO_RD_BYTE_S) & UART_RXFIFO_RD_BYTE;
                return ch;
            }
            WRITE_PERI_REG(UART_INT_CLR(GDB_UART), UART_RXFIFO_FULL_INT_ST | UART_RXFIFO_TOUT_INT_ST);
        }
        // if (status & UART_TXFIFO_EMPTY_INT_ST) ...
        // if (status & UART_RXFIFO_OVF_INT_ST) ...
    }
}

ICACHE_FLASH_ATTR
void gdb_restore_state() {
    os_install_putc1(real_putc1);
    for (;;); // XXX too bad
}

static bool gdb_read_err, gdb_read_dollar;
static uint8_t gdb_read_cksum;

ICACHE_FLASH_ATTR
void gdb_read_reset() {
    gdb_read_err = false;
    gdb_read_dollar = false;
    gdb_read_cksum = 0;
}

ICACHE_FLASH_ATTR
char gdb_read_char() {
    if (gdb_read_err) {
        return 0;
    }
    char ch = real_getc1();
    if (!gdb_read_dollar) {
        while (ch != '$') { // jump to the packet start
            ch = real_getc1();
        }
        gdb_read_dollar = true;
        ch = real_getc1();
    }
    if (ch == '#') {
        gdb_read_err = true;
    } else {
        gdb_read_cksum += ch;
    }
    return ch;
}

static uint8_t gdb_write_cksum;
static bool wrote_dollar;

ICACHE_FLASH_ATTR
void gdb_write_string(char *buf) {
    if (!wrote_dollar) {
        wrote_dollar = true;
        real_putc1('$');
    }
    for (; *buf; ++buf) {
        gdb_write_cksum += *buf;
        real_putc1(*buf);
    }
}

ICACHE_FLASH_ATTR
void gdb_write_reset() {
    gdb_write_cksum = 0;
    wrote_dollar = false;
}

ICACHE_FLASH_ATTR
void gdb_write_byte(uint8_t b) {
    char buf[3];
    os_sprintf(buf, "%02x", b);
    gdb_write_string(buf);
}

ICACHE_FLASH_ATTR
void gdb_write_flush() {
    gdb_write_string("");
    real_putc1('#');
    gdb_write_byte(gdb_write_cksum);
}

static char outbuf[256];
static uint16_t outbuf_head, outbuf_tail;
ICACHE_FLASH_ATTR
void gdb_putc1(char c) {
    outbuf[outbuf_tail++] = c;
    outbuf_tail %= sizeof(outbuf);
}

ICACHE_FLASH_ATTR
void gdb_install_io() {
    outbuf_head = outbuf_tail = 0;
    //ets_install_putc1(gdb_putc1);
}

ICACHE_FLASH_ATTR
uint8_t gdb_read_byte() {
    uint8_t a = gdb_read_char() & 0x4f;
    a = (a & 0xf) + 9 * (a >> 6);
    uint8_t b = gdb_read_char() & 0x4f;
    b = (b & 0xf) + 9 * (b >> 6);
    return (a << 4) | b;
}

ICACHE_FLASH_ATTR
bool gdb_read_to_cksum() {
    while (!gdb_read_err) {
        gdb_read_char();
    }
    // Error, we hit '#'. Clear the error and read the cksum
    gdb_read_err = false;
    uint8_t cksum = gdb_read_cksum;
    uint8_t host_cksum = gdb_read_byte();
    bool ret = host_cksum == cksum;
    real_putc1(ret ? '+' : '-');
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
uint8_t gdb_read_memory(size_t addr) {
    if (!(0x20000000 <= addr && addr < 0x60001800)) {
        return 0;
    }
    return *(size_t *)(addr & ~3) >> (8 * (addr & 3));
}

ICACHE_FLASH_ATTR
void gdb_attach() {
    bool has_breakpoint = false, has_watchpoint = false;
    size_t breakpoint_addr;
    size_t saved_ps;
    size_t saved_wdt_mode = ets_wdt_get_mode();
    ets_wdt_disable();
    char buf[18];
    __asm__("rsil %0, 15":"+r"(saved_ps));
    gdb_install_io();

    gdb_write_reset();
    gdb_write_string("vStopped");
    gdb_write_flush();

    for (;;) {
#define GDB_READ() \
    if (!gdb_read_to_cksum()) { \
        goto retrans; \
    }
        gdb_write_reset();
        {
            int diff = outbuf_tail - outbuf_head;
            if (diff) {
                uint16_t start, end;
                if (diff < 0) {
                    start = outbuf_head;
                    end = sizeof(outbuf);
                    outbuf_head = 0;
                } else {
                    start = 0;
                    end = outbuf_tail;
                    outbuf_head = outbuf_tail;
                }
                gdb_write_string("Fwrite,1,");
                os_sprintf(buf, "%08x,%08x", ((size_t)outbuf) + start, (uint16_t)(end - start));
                gdb_write_string(buf);
                goto next;
            }
        }
retrans:
        gdb_read_reset();
        {
            char cmd = gdb_read_char();
            if (gdb_read_err) {
                GDB_READ();
                goto next;
            }
            size_t addr, len;
            switch (cmd) {
                case '?':
                    GDB_READ();
                    gdb_write_string("S09");
                    break;
                case 'D':
                case 'c': {
                    size_t pc = gdb_read_int();
                    bool set_pc = !gdb_read_err;
                    GDB_READ();
                    if (set_pc) {
                        regs.pc.value = pc;
                    } else if (!regs.pc.valid) {
                        gdb_write_string("E01");
                        goto cont;
                    }
                    gdb_write_string("OK");
                    goto cont;
                }
                // read addr, length
                case 'm':
                    addr = gdb_read_int();
                    len = gdb_read_int();
                    GDB_READ();
                    for (; len; ++addr, --len) {
                        gdb_write_byte(gdb_read_memory(addr));
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
                case 'p':
                    {
                        uint8_t reg_i;
                        if (cmd == 'p') {
                            reg_i = gdb_read_byte();
                        }
                        GDB_READ();
                        int begin_i = 0, end_i = sizeof(regs) / sizeof(struct GdbRegister);
                        if (cmd == 'p') {
                            if (!(begin_i <= reg_i && reg_i < end_i)) {
                                gdb_write_string("E04");
                                break;
                            }
                            begin_i = reg_i;
                            end_i = begin_i + 1;
                        }
                        struct GdbRegister *begin = (struct GdbRegister *)&regs + begin_i;
                        struct GdbRegister *end = (struct GdbRegister *)&regs + end_i;
                        for (; end - begin; ++begin) {
                            os_strcpy(buf, "x*%");
                            if (begin->valid) {
                                int i;
                                for (i = 0; i < 4; ++i) {
                                    os_sprintf(&buf[2 * i], "%02x", ((char *)&begin->value)[i]);
                                }
                            }
                            gdb_write_string(buf);
                        }
                    }
                    break;
                case 'z':
                case 'Z': {
                    char type = gdb_read_char();
                    size_t kind; // not used
                    if (1 <= type && type <= 4) {
                        addr = gdb_read_int();
                        kind = gdb_read_int();
                    }
                    GDB_READ();
                    if (type == 1) {
                        switch (cmd) {
                            case 'z':
                                if (!has_breakpoint) {
                                    break;
                                }
                                __asm__("wsr.ibreakenable %0"::"r"(0));
                                break;
                            case 'Z':
                                if (has_breakpoint) {
                                    if (addr == breakpoint_addr) {
                                        break;
                                    }
                                    gdb_write_string("E00");
                                    break;
                                }
                                __asm__("wsr.ibreaka0 %0"::"r"(addr));
                                __asm__("wsr.ibreakenable %0"::"r"(1));
                                break;
                        }
                    } else if (2 <= type && type <= 4) {
                        if (!kind || (kind != (kind & -kind)) || (kind > 64)) {
                            break; // kind must be 1, 2, ..., 64
                        }
                        switch (cmd) {
                            case 'z':
                                if (!has_watchpoint) {
                                    break;
                                }
                                __asm__("wsr.dbreakc0 %0"::"r"(0));
                                break;
                            case 'Z':
                                if (has_watchpoint) {
                                    if (addr == breakpoint_addr) {
                                        break;
                                    }
                                    gdb_write_string("E03");
                                    break;
                                }
                                size_t dbreakc = 0;
                                if (type != 2) { // write
                                    dbreakc |= XCHAL_DBREAKC_LOADBREAK_MASK;
                                }
                                if (type != 3) { // read
                                    dbreakc |= XCHAL_DBREAKC_STOREBREAK_MASK;
                                }
                                dbreakc |= (kind - 1) ^ 63;
                                __asm__("wsr.dbreaka0 %0"::"r"(addr));
                                __asm__("wsr.dbreakc0 %0"::"r"(dbreakc));
                                break;
                        }
                    } else {
                        break;
                    }
                    gdb_write_string("OK");
                    break;
                }
#undef EXPECT_REG
                case 'k':
                    system_restart();
                    break;
                // no reply
                case 'F': // io reply
                    GDB_READ();
                    continue;
                // qXfer:memory-map:read
                case 'q':
                // i [addr [instruction count]]
                case 'i':
                // unsupported
                default:
                    GDB_READ();
                    break;
            }
        }
next:
        gdb_write_flush();
#undef GDB_READ
    }
cont:
    ets_wdt_restore(saved_wdt_mode);
    __asm__("wsr.ps %0"::"r"(saved_ps));
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
    size_t excvaddr, litbase, epc, excsave;
    __asm__("rsr.excvaddr %0":"=r"(excvaddr));
    __asm__("rsr.litbase %0":"=r"(litbase));
    __asm__("rsr.epc1 %0":"=r"(epc));
    __asm__("rsr.excsave1 %0":"=r"(excsave));
    os_memset(&regs, 0, sizeof(regs));
#define REGISTER_ARG(x, arg) do { \
    regs.x.value = arg; \
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
    REGISTER_ARG(sr176, epc); // actually sr177
    REGISTER_ARG(sr208, excsave); // actually sr209
#undef REGISTER
#undef REGISTER_ARG

    user_dprintf("vpri=%d exccause=%d excvaddr=%p pc=%p", frame->vpri, frame->exccause, (void *)excvaddr, (void *)frame->pc);
    if (excvaddr * excvaddr == 3) { // impossible due to quadratic reciprocity
        gdb_stub_DebugExceptionVector(); // reference the symbol
    }
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
