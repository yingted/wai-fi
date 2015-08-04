#ifndef __USER_CONFIG_H__
#define __USER_CONFIG_H__

#include <osapi.h>
#include <xtensa/corebits.h>

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
        print_stack(); \
        gdb_stub_break_force(); \
        system_restart(); \
    } \
} while (0)
#endif

#include "gdb_stub.h"
#include "debug_esp.h"

// fix header conflict
#include <ip_addr.h>
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

#ifndef DEBUG_ESP
#define USER_INTR_LOCK() ets_intr_lock()
#define USER_INTR_UNLOCK() ets_intr_unlock()
#else

/**
 * The invariant of a reentrant interrupt lock is that only one intlevel can
 * hold the lock at a time.
 */
#define USER_INTR_LOCK() do { \
    size_t ps; \
    __asm__ __volatile__("rsr %0, ps":"=r"(ps)); \
    assert(intr_lock_count[PS_INTLEVEL(ps)]++ == intr_lock_count_sum++); \
    ets_intr_lock(); \
} while (0)

#define USER_INTR_UNLOCK() do { \
    ets_intr_unlock(); \
    size_t ps; \
    __asm__ __volatile__("rsr %0, ps":"=r"(ps)); \
    assert(--intr_lock_count[PS_INTLEVEL(ps)] == --intr_lock_count_sum); \
} while (0)

#endif

#define USER_DATA32_ATTR /*__attribute__((aligned(4))) ICACHE_RODATA_ATTR*/

#endif

