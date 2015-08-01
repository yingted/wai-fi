#include "user_config.h"
#include "user_interface.h"
#include "debug_esp.h"
#include "connmgr.h"
#include "espconn.h"

ICACHE_FLASH_ATTR
void user_rf_pre_init(void) {
    debug_esp_install_exc_handler();
}

ICACHE_FLASH_ATTR
void user_init(void) {
    system_update_cpu_freq(160);
    uart_div_modify(0, UART_CLK_FREQ / 115200);
    user_dprintf("set cpu freq to %d", system_get_cpu_freq());

    connmgr_init();
    connmgr_start();
}

static bool can_send = false;

ICACHE_FLASH_ATTR
void connmgr_connect_cb(struct espconn *conn) {
    user_dprintf("%p", conn);
    can_send = true;
}

#define LOGBUF_SIZE 2048
static struct pbuf *logbuf_head = NULL, *logbuf_tail = NULL;

/**
 * Try to send logbuf_head.
 * Must have intr lock.
 */
ICACHE_FLASH_ATTR
void try_send_log() {
    if (can_send && logbuf_head != logbuf_tail) {
        struct pbuf *const to_send = logbuf_head;
        logbuf_head = pbuf_dechain(logbuf_head);
        size_t logged_size = LOGBUF_SIZE - logbuf_head->len;
        can_send = false;
        espconn_secure_sent(&conn, (char *)logbuf_head->payload - logged_size, logged_size);
    }
}

ICACHE_FLASH_ATTR
void connmgr_sent_cb(struct espconn *conn) {
    user_dprintf("%p", conn);

    assert(can_send == false);
    USER_INTR_LOCK();
    can_send = true;
    try_send_log();
    USER_INTR_UNLOCK();
}

ICACHE_FLASH_ATTR
void connmgr_recv_cb(struct espconn *conn, char *buf, unsigned short len) {
    user_dprintf("%p", conn);

    os_printf("buf: ");
    for (; len > 0; ++buf, --len) {
        os_printf("%c", *buf);
    }
    // TODO
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
        u8_t num_bufs = 0;

        if (logbuf_head) {
            num_bufs = pbuf_clen(logbuf_head);
        }
        if (num_bufs >= 5) {
            user_dprintf("hit alloc limit");
            goto out;
        }

        user_dprintf("allocating new buf");
        struct pbuf *new_tail = pbuf_alloc(PBUF_RAW, LOGBUF_SIZE, PBUF_RAM);
        if (!new_tail) {
            user_dprintf("dropping log entry");
            goto out;
        }
        logbuf_tail = new_tail;
        if (logbuf_head) {
            pbuf_cat(logbuf_head, logbuf_tail);
            try_send_log();
        } else {
            logbuf_head = logbuf_tail;
        }
    }

    struct logentry *const dst = ((struct logentry *)logbuf_tail->payload) - 1;
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
