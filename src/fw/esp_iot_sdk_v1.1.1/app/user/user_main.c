#include "user_config.h"
#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"
#include "user_interface.h"
#include "icmp_net.h"
#include "lwip/ip4.h"
#include "lwip/netif/etharp.h"
#include "lwip/sockets.h"
#include "espconn.h"

static struct netif icmp_tap;
static struct icmp_net_config icmp_config;
static struct ip_info linklocal_info = {
    .ip = { IPADDR_ANY },
    .netmask = { IPADDR_ANY },
    .gw = { IPADDR_ANY },
};
bool secure_connected = false;
struct espconn con;

#define assert_heap() assert_heap_(__FILE__, __LINE__)
void assert_heap_(char *file, int line);

ICACHE_FLASH_ATTR
static void espconn_connect_cb(void *arg) {
    user_dprintf("arg=%p", arg);
    assert_heap();
}

static void connect_ssl();
ICACHE_FLASH_ATTR
static void schedule_reconnect() {
    //espconn_secure_disconnect(&con);
    secure_connected = false;
    assert_heap();
    //sys_timeout(1000, connect_ssl, NULL);
    connect_ssl();
}

ICACHE_FLASH_ATTR
static void espconn_reconnect_cb(void *arg, sint8 err) {
    user_dprintf("reconnect due to %d", err);
    schedule_reconnect();
}

ICACHE_FLASH_ATTR
static void espconn_disconnect_cb(void *arg) {
    schedule_reconnect();
}

ICACHE_FLASH_ATTR
static void connect_ssl() {
    os_memset(&con, 0, sizeof(con));
    con.type = ESPCONN_TCP;
    con.state = ESPCONN_NONE;
    {
        static esp_tcp tcp;
        memset(&tcp, 0, sizeof(tcp));
        tcp.remote_port = 55555;
        os_memcpy(tcp.local_ip, &icmp_tap.ip_addr, sizeof(struct ip_addr));
        os_memcpy(tcp.remote_ip, &icmp_tap.gw, sizeof(struct ip_addr));

        con.proto.tcp = &tcp;
    }
    assert_heap();
    espconn_regist_connectcb(&con, espconn_connect_cb);
    espconn_regist_reconcb(&con, espconn_reconnect_cb);
    espconn_regist_disconcb(&con, espconn_disconnect_cb);
    assert_heap();

    user_dprintf("starting connection");
    assert_heap();
    ets_intr_lock();
    sint8 rc = espconn_secure_connect(&con);
    ets_intr_unlock();
    user_dprintf("started connection: %d", rc);
    assert_heap();
    if (rc) {
        user_dprintf("espconn_secure_connect: error %u", rc);
        return;
    }
    secure_connected = true;
}

ICACHE_FLASH_ATTR
void wifi_handle_event_cb(System_Event_t *event) {
    assert_heap();
    static struct netif *saved_default = NULL;
    switch (event->event) {
        case EVENT_STAMODE_GOT_IP:
            user_dprintf("ip " IPSTR " mask " IPSTR " gw " IPSTR,
                      IP2STR(&event->event_info.got_ip.ip),
                      IP2STR(&event->event_info.got_ip.mask),
                      IP2STR(&event->event_info.got_ip.gw));
            assert_heap();

            icmp_net_enslave(&icmp_config, ip_route(&event->event_info.got_ip.gw));

            if (netif_default != &icmp_tap) {
                assert(saved_default == NULL);
                saved_default = netif_default;
                netif_default = &icmp_tap;

                err_t rc = dhcp_start(&icmp_tap);
                if (rc != ERR_OK) {
                    user_dprintf("dhcp error: %d", rc);
                }
            } else {
                user_dprintf("tunnel established");
                connect_ssl();
            }
            break;
        case EVENT_STAMODE_DISCONNECTED:
            user_dprintf("disconnected");

            if (secure_connected) {
                espconn_secure_disconnect(&con);
            }

            dhcp_stop(&icmp_tap);

            icmp_net_unenslave(&icmp_config);

            if (netif_default == &icmp_tap) {
                netif_default = saved_default;
                saved_default = NULL;
            }
        case EVENT_STAMODE_CONNECTED:
            user_dprintf("connected");
            assert_heap();
            break;
        case EVENT_STAMODE_AUTHMODE_CHANGE:
            user_dprintf("unknown event authmode_change");
            break;
        default:
            user_dprintf("unknown event %d", event->event);
    }

    user_dprintf("done");
    assert_heap();
}

ICACHE_FLASH_ATTR
void user_rf_pre_init(void) {
}

ICACHE_FLASH_ATTR
void user_init(void) {
    uart_div_modify(0, UART_CLK_FREQ / 115200);
    user_dprintf("user_init()");
    user_dprintf("heap: %d", system_get_free_heap_size());
    assert_heap();

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

    wifi_set_event_handler_cb(wifi_handle_event_cb);

    user_dprintf("done");
    assert_heap();
}
