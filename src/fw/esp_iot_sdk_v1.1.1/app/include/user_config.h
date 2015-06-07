#ifndef __USER_CONFIG_H__
#define __USER_CONFIG_H__

#ifdef NDEBUG
#define user_dprintf(...)
#else
#define user_dprintf(...) do { \
    os_printf("%s: ", __func__); \
    os_printf(__VA_ARGS__); \
    os_printf("\n"); \
} while (0)
#endif

#include "ip_addr.h"
#define LWIP_OPEN_SRC

#endif

