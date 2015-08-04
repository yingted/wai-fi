#ifndef __USER_CONFIG_H__
#define __USER_CONFIG_H__

#include <osapi.h>

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
        system_restart(); \
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

#include <ssl/ssl_ssl.h>
#include <ssl/ssl_tls1.h>
struct tcp_pcb;
EXP_FUNC SSL *STDCALL SSLClient_new(SSL_CTX *ssl_ctx, struct tcp_pcb *SslClient_pcb, const
                                                uint8_t *session_id, uint8_t sess_id_size);

#define USER_MEM_BARRIER() __sync_synchronize()

#define USER_INTR_LOCK() do { \
    ets_intr_lock(); \
    /*USER_MEM_BARRIER();*/ \
} while (0)

#define USER_INTR_UNLOCK() do { \
    /*USER_MEM_BARRIER();*/ \
    ets_intr_lock(); \
} while (0)

#define USER_DATA32_ATTR /*__attribute__((aligned(4))) ICACHE_RODATA_ATTR*/

#endif

