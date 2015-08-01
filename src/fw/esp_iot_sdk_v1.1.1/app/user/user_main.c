#include "user_config.h"
#include "user_interface.h"
#include "debug_esp.h"
#include "connmgr.h"

ICACHE_FLASH_ATTR
void user_rf_pre_init(void) {
    debug_esp_install_exc_handler();
}

ICACHE_FLASH_ATTR
void user_init(void) {
    system_update_cpu_freq(160);
    uart_div_modify(0, UART_CLK_FREQ / 115200);
    user_dprintf("set cpu freq to %d", system_get_cpu_freq());
    //wifi_promiscuous_enable(0);

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
void connmgr_packet_cb(uint8_t *payload, short header_len, short body_len, int rssi) {
    user_dprintf("len=%d+%d, rssi=%d", header_len, body_len, rssi);
    if (header_len >= 24) {
        os_printf("packet: ");
        int i;
        for (i = 0; i < 24; ++i) {
            os_printf("%02x", payload[i]);
        }
        os_printf("\n");
    }
}

ICACHE_FLASH_ATTR
void connmgr_disconnect_cb() {
    user_dprintf("");

    // TODO
}
