#include "user_config.h"
#include "promisc.h"

ICACHE_FLASH_ATTR
void promisc_start() {
    wDevDisableRx();
    //size_t flags = 0b11011110011111100111; // tx, no rx
    //size_t flags = 0b00000000011111100000; // broken
    //size_t flags = 0b00000000010101100000; // works
    size_t flags = 0b11011110000001100111;
    //               66s2555550000564g666
    //flags = 0;
    extern char g_ic[0];
    size_t *a6 = (size_t *)0x3ff1fe00;
    size_t *a2 = (size_t *)0x60009a00;
    size_t *a10 = (size_t *)0x3ff20600;
    extern size_t wDevCtrl[0];
    size_t *a4 = wDevCtrl;
    size_t *a5 = (size_t *)0x3ff20a00;
    {
        if (flags & 0x1)
            a6[0x26c / 4] &= ~1;
        if (flags & 0x2)
            a6[0x26c / 4] &= ~2;
        if (flags & 0x4)
            a6[0x26c / 4] &= ~4;

        if (flags & 0x8)
            (g_ic + 0x180)[100] = 1;

        if (flags & 0x10)
            ((char *)a4)[5] = 1;
    }
    {
        if (flags & 0x20)
            a6[0x20c / 4] = a4[12];

        if (flags & 0x40)
            a5[0x288 / 4] |= 0x00040000;

        if (flags & 0x80)
            a10[0x200 / 4] |= 0x03000000;
        if (flags & 0x100)
            a10[0x200 / 4] &= ~0x00010000;
        if (flags & 0x200)
            a10[0x204 / 4] |= 0x03000000;
        if (flags & 0x400)
            a10[0x204 / 4] &= ~0x00010000;

        if (flags & 0x800)
            a5[0x258 / 4] = 0;
        if (flags & 0x1000)
            a5[0x25c / 4] = 0x00010000;
        if (flags & 0x2000)
            a5[0x238 / 4] = 0;
        if (flags & 0x4000)
            a5[0x23c / 4] = 0x00010000;
        if (flags & 0x8000)
            a5[0x218 / 4] |= 12;

        if (flags & 0x10000)
            a2[0x344 / 4] &= ~0x24000000;

        if (flags & 0x20000)
            ets_delay_us(15000);

        if (flags & 0x40000)
            a6 = (size_t *)a5;
        if (flags & 0x80000)
            a6[0x294 / 4] &= ~1;
    }
    assert((g_ic + 0x180)[100] != 1);
    wDevEnableRx();
}
