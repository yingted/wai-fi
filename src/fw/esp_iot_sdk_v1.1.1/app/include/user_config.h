#ifndef __USER_CONFIG_H__
#define __USER_CONFIG_H__

#ifdef NDEBUG
#define user_dprintf(...)
#define assert(...)
#else
#define user_dprintf(...) do { \
    os_printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
    os_printf(__VA_ARGS__); \
    os_printf("\n"); \
} while (0)
#define assert(arg) do { \
    if (!(arg)) { \
        user_dprintf("assertion failed: %s", #arg); \
        for (;;); \
    } \
} while (0)
#endif

// fix header conflict
#include "ip_addr.h"
#define LWIP_OPEN_SRC

// I don't understand why this is necessary for ABI compatibility
#define mtu mtu __attribute__((aligned(4)))
#include <lwip/netif.h>
#undef mtu

#endif

