#include "user_config.h"
#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"
#include "user_interface.h"
#include "icmp_net.h"
#include "lwip/ip4.h"
#include "lwip/netif/etharp.h"
#include "lwip/sockets.h"
#include "ssl/ssl_ssl.h"
#include "ssl/ssl_tls1.h"

static struct netif icmp_tap;
static struct icmp_net_config icmp_config;
static struct ip_info linklocal_info = {
    .ip = { IPADDR_ANY },
    .netmask = { IPADDR_ANY },
    .gw = { IPADDR_ANY },
};
int ssl_fd;
static SSL_CTX *ssl_ctx;
static SSL *ssl = NULL;
static uint8_t session_id[32], session_id_size = 0;

ICACHE_FLASH_ATTR
static inline void on_tunnel_established() {
    user_dprintf("tunnel established");

    ssl_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ssl_fd < 0) {
        user_dprintf("socket: error %d", ssl_fd);
        return;
    }

    connect(...);

    ssl = SSLClient_new(ssl_ctx, ssl_fd, session_id_size ? session_id : NULL, session_id_size);
    if (ssl == NULL) {
        user_dprintf("ssl_client_new: failed");
        close(ssl_fd);
        return;
    }

    // TODO asyncify
    int rc;
    while (ssl_handshake_status(ssl) != SSL_OK) {
        rc = ssl_read(ssl, NULL);
        user_dprintf("ssl_read: %d", rc);
        if (rc < SSL_OK)
            break;
    }

    ssl->hs_status = rc;

    if (rc != SSL_OK) {
        user_dprintf("ssl: handshake failure %d", rc);
        return;
    }

    assert(ssl_get_session_id(ssl));
    os_memcpy(session_id, ssl_get_session_id(ssl),
        session_id_size = ssl_get_session_id_size(ssl));

    user_dprintf("ssl: connected");
}

ICACHE_FLASH_ATTR
void wifi_handle_event_cb(System_Event_t *event) {
    struct netif *saved_default = NULL;
    switch (event->event) {
        case EVENT_STAMODE_GOT_IP:
            user_dprintf("ip " IPSTR " mask " IPSTR " gw " IPSTR,
                      IP2STR(&event->event_info.got_ip.ip),
                      IP2STR(&event->event_info.got_ip.mask),
                      IP2STR(&event->event_info.got_ip.gw));

            icmp_config.slave = ip_route(&event->event_info.got_ip.gw);

            assert(saved_default == NULL);
            if (netif_default != &icmp_tap) {
                saved_default = netif_default;
                netif_default = &icmp_tap;

                err_t rc = dhcp_start(&icmp_tap);
                if (rc != ERR_OK) {
                    user_dprintf("dhcp error: %d", rc);
                }
            } else {
                on_tunnel_established();
            }
            break;
        case EVENT_STAMODE_DISCONNECTED:
            user_dprintf("disconnected");

            if (ssl) {
                ssl_free(ssl);
                close(ssl_fd);
            }

            dhcp_stop(&icmp_tap);

            if (netif_default == &icmp_tap) {
                netif_default = saved_default;
                saved_default = NULL;
            }
        case EVENT_STAMODE_CONNECTED:
            break;
        case EVENT_STAMODE_AUTHMODE_CHANGE:
            user_dprintf("unknown event authmode_change");
            break;
        default:
            user_dprintf("unknown event %d", event->event);
    }
}

ICACHE_FLASH_ATTR
void user_rf_pre_init(void) {
}

ICACHE_FLASH_ATTR
void user_init(void) {
    uart_div_modify(0, UART_CLK_FREQ / 115200);
    user_dprintf("user_init()");

    wifi_set_opmode_current(STATION_MODE);
    {
        struct station_config *config = (struct station_config *)os_zalloc(sizeof(struct station_config));
        const static char *ssid = "icmp-test";
        os_memcpy(config->ssid, ssid, os_strlen(ssid));
        wifi_station_set_config_current(config);
    }
    wifi_station_set_auto_connect(1);
    wifi_station_set_reconnect_policy(true);

    icmp_config.relay_ip.addr = ipaddr_addr("192.168.9.1");

    // Create the ICMP tap device and never delete it.
    if (!netif_add(
            &icmp_tap,
            &linklocal_info.ip,
            &linklocal_info.netmask,
            &linklocal_info.gw,
            &icmp_config,
            icmp_net_init,
            ethernet_input
        )) {
        user_dprintf("netif_add failed");
    }

    ssl_ctx = ssl_ctx_new(SSL_CONNECT_IN_PARTS, 1);
    // TODO ssl_obj_memory_load(...)

    wifi_set_event_handler_cb(wifi_handle_event_cb);
}
