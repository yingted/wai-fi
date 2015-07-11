#include "user_config.h"
#include "user_interface.h"
#include "debug_esp.h"
#include "connmgr.h"

ICACHE_FLASH_ATTR
void user_rf_pre_init(void) {
    debug_esp_install_exc_handler();
}

struct sta_input_pkt {
    char pad_0_[4];
    struct {
        char pad_0_[4];
        uint8_t *payload;
    } *packet;
    char pad_8_[20 - 8];
    short header_len;
    short body_len;
    // byte 24
};

int __real_sta_input(void *ni, struct sta_input_pkt *m, int rssi, int nf);
ICACHE_FLASH_ATTR
int __wrap_sta_input(void *ni, struct sta_input_pkt *m, int rssi, int nf) {
#if 0
    user_dprintf("sta_input: %p %d", m, rssi);
    assert(nf == 0);
    assert(m->packet->payload == ((unsigned char ***)m)[1][1]);
    assert(m->header_len == (int)((short *)m)[10]);
    assert(m->body_len == (int)((short *)m)[11]);
    int i, len = m->header_len + m->body_len;
    os_printf("payload (len=%d+%d): ", m->header_len, m->body_len);
    for (i = 0; i < len; ++i) {
        os_printf("%02x", m->packet->payload[i]);
    }
    os_printf("\n");
#endif
    return __real_sta_input(ni, m, rssi, nf);
}

ICACHE_FLASH_ATTR
void user_init(void) {
    system_update_cpu_freq(160);
    uart_div_modify(0, UART_CLK_FREQ / 115200);
    user_dprintf("set cpu freq to %d", system_get_cpu_freq());

    connmgr_init();
    connmgr_start();
}

ICACHE_FLASH_ATTR
void connmgr_connect_cb(struct espconn *conn) {
    user_dprintf("%p", conn);

    // TODO
    char buf[] = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\n'};
    espconn_secure_sent(conn, buf, sizeof(buf));
}

ICACHE_FLASH_ATTR
void connmgr_sent_cb(struct espconn *conn) {
    user_dprintf("%p", conn);

    // TODO
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
void connmgr_disconnect_cb() {
    user_dprintf("");

    // TODO
}
