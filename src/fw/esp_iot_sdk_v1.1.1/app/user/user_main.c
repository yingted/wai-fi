#include <user_config.h>
#include <user_interface.h>
#include <debug_esp.h>
#include <connmgr.h>
#include <gdb_stub.h>
#include <lwip/netif.h>
#include <waifi_rpc.h>

#define LOGBUF_SIZE 1024
#define MAX_LOGBUF 3

__attribute__((weak))
ICACHE_FLASH_ATTR
void user_rf_pre_init(void) {}

#ifndef UART_LOGGING
ICACHE_FLASH_ATTR
static void noop_put1c() {}
#endif

ICACHE_FLASH_ATTR
void user_init(void) {
    system_update_cpu_freq(160);
    uart_div_modify(0, UART_CLK_FREQ / 115200);
#ifndef UART_LOGGING
    os_install_putc1(noop_put1c);
#endif
    debug_esp_install_exc_handler();
    gdb_stub_init();
#ifdef GDB_STUB_STARTUP
    gdb_stub_break();
#endif
    user_dprintf("Starting up...");

    connmgr_init();
    connmgr_start();
}

enum { MSG_LOG=0 };
struct msg_header {
    char type;
    char pad_;
    union {
        struct {
            s16_t len;
            // ...
        } log;
    };
};
static struct pbuf *logbuf_head = NULL, *logbuf_tail = NULL;
static bool can_send = false;

/**
 * Try to send logbuf_head.
 * Must have intr lock.
 */
ICACHE_FLASH_ATTR
void try_send_log() {
    if (can_send && logbuf_head != logbuf_tail) {
        struct pbuf *const to_send = logbuf_head;
        assert(to_send);
        pbuf_ref(logbuf_head = to_send->next);
        assert(logbuf_head);
        assert(pbuf_clen(to_send) > 1);
        pbuf_dechain(to_send);
        assert(logbuf_head->ref >= 1);
        size_t logged_size = LOGBUF_SIZE - to_send->len;
        struct msg_header *header = (struct msg_header *)((char *)to_send->payload - logged_size);
        switch (header->type) {
            case MSG_LOG:
                header->log.len = htons((short)(logged_size - sizeof(*header)));
                break;
            default:
                assert(false);
        }
        can_send = false;
        if (pbuf_header(to_send, logged_size)) {
            assert(false);
        }
        pbuf_realloc(to_send, logged_size);
        if (connmgr_send(to_send) != ERR_OK) {
            assert(false); // not implemented
        }
    }
}

ICACHE_FLASH_ATTR
void set_can_send() {
    assert(can_send == false);
    USER_INTR_LOCK();
    can_send = true;
    try_send_log();
    USER_INTR_UNLOCK();
}

ICACHE_FLASH_ATTR
void connmgr_connect_cb() {
    set_can_send();
}

ICACHE_FLASH_ATTR
void connmgr_sent_cb() {
    set_can_send();
}

ICACHE_FLASH_ATTR
void connmgr_recv_cb(char *buf, unsigned short len) {
    os_printf("buf: ");
    for (; len > 0; ++buf, --len) {
        os_printf("%c", *buf);
    }
    user_dprintf("userbin=%d", system_upgrade_userbin_check());
    if (len > 0) {
        switch (buf[0]) {
            case WAIFI_RPC_system_upgrade_userbin_check:
                break;
            case WAIFI_RPC_spi_flash_write:
                break;
        }
    }
}

ICACHE_FLASH_ATTR
void connmgr_packet_cb(uint8_t *payload, short header_len, short body_len, int rssi) {
    struct logentry {
        uint8_t header_prefix[24];
        char rssi;
    };
    _Static_assert(sizeof(struct logentry) == 25, "wrong struct size");
    if (header_len < sizeof(((struct logentry *)NULL)->header_prefix)) {
        return;
    }

    USER_INTR_LOCK();
    while (!logbuf_tail || pbuf_header(logbuf_tail, -(s16_t)sizeof(struct logentry))) {
        {
            u8_t num_bufs = 0;

            if (logbuf_head) {
                num_bufs = pbuf_clen(logbuf_head);
            }
            if (num_bufs >= MAX_LOGBUF) {
                goto out;
            }
        }

        user_dprintf("allocating new buf");
        struct pbuf *new_tail = pbuf_alloc(PBUF_RAW, LOGBUF_SIZE, PBUF_RAM);
        assert(new_tail->len == LOGBUF_SIZE);
        if (!new_tail) {
            user_dprintf("dropping log entry");
            goto out;
        }

        {
            _Static_assert(sizeof(struct msg_header) == 4, "msg header wrong size");
            struct msg_header *const header = (struct msg_header *)new_tail->payload;
            pbuf_header(new_tail, -(u16_t)sizeof(*header));
            os_memset(header, 0, sizeof(*header));
            header->type = MSG_LOG;
        }

        logbuf_tail = new_tail;
        if (logbuf_head) {
            pbuf_cat(logbuf_head, logbuf_tail);
            try_send_log();
        } else {
            logbuf_head = logbuf_tail;
        }
    }

    struct logentry *const dst = (struct logentry *)logbuf_tail->payload - 1;
    os_memcpy(dst->header_prefix, payload, sizeof(dst->header_prefix));
    dst->rssi = rssi;

out:
    USER_INTR_UNLOCK();
}

ICACHE_FLASH_ATTR
void connmgr_disconnect_cb() {
    user_dprintf("");
    can_send = false;
}
