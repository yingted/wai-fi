#ifndef __USER_CONFIG_H__
#define __USER_CONFIG_H__

#include <osapi.h>
#include <xtensa/corebits.h>
#include <espressif/c_types.h>

#ifdef NDEBUG
#define user_dprintf(...)
#define assert(...)
#else
#define user_dprintf(fmt, ...) os_printf("%s:%d %s: " fmt "\n", __FILE__, __LINE__, __func__, ## __VA_ARGS__)

#include <debug_esp.h>

#define assert(arg) do { \
    if (!(arg)) { \
        user_dprintf("assertion failed: %s", #arg); \
        debug_esp_fatal(); \
    } \
} while (0)
#endif

// fix header conflict
#include <ip_addr.h>
#define LWIP_OPEN_SRC
// Espressif-ness
#define TCP_TMR_INTERVAL 125

// I don't understand why this is necessary for ABI compatibility
#define mtu mtu __attribute__((aligned(4)))
#include <lwip/netif.h>
#undef mtu

// Okay, this is just messed up.
#include <lwip/tcp.h>
struct user_tcp_pcb {
    IP_PCB; // IPv4 takes up [0, 11)
    char pad_12_[12 - 11];
    struct user_tcp_pcb *next; // [12, 16)
    char pad_16_[20 - 16];
    u8_t prio; // [20, 21)
    void *callback_arg; // [20, 24)
    char pad_24_[60 - 24];
    u16_t mss; // [60, 62)
    char pad_62_[148 - 62];
    tcp_err_fn errf; // [148, 152)
    u32_t keep_idle; // [152, 156)
    u32_t keep_intvl; // [156, 160)
    u32_t keep_cnt; // [160, 164)
};

#include <ssl/ssl_ssl.h>
#include <ssl/ssl_tls1.h>
extern int send_raw_packet(SSL *ssl, uint8_t protocol);
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
#define USER_INTR_LOCK() debug_esp_user_intr_lock()
#define USER_INTR_UNLOCK() debug_esp_user_intr_unlock()

#endif

// The latest SDK screws this up
#undef ICACHE_FLASH_ATTR
#define ICACHE_FLASH_ATTR __attribute__((section(".irom0.text")))
#define USER_DATA32_ATTR /*__attribute__((aligned(4))) ICACHE_RODATA_ATTR*/

// Espressif APIs
extern void ppRecycleRxPkt(void *);
void ets_intr_lock(void);
void ets_intr_unlock(void);
size_t ets_wdt_get_mode();
void ets_wdt_restore(size_t mode);
void ets_wdt_disable();

#endif

