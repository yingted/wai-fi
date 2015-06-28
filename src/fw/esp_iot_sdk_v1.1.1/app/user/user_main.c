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

static void connect_ssl();
ICACHE_FLASH_ATTR
static void schedule_reconnect() {
    assert_heap();

    USER_INTR_LOCK();
    if (!secure_connected) {
        user_dprintf("warning: disconnect: already disconnected");
        return;
    }
    secure_connected = false;
    //sys_timeout(1000, connect_ssl, NULL);
    connect_ssl();
    USER_INTR_UNLOCK();
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
static void espconn_sent_cb(void *arg) {
    user_dprintf("%p", arg);

    // TODO
}

ICACHE_FLASH_ATTR
static void espconn_recv_cb(void *arg, char *buf, unsigned short len) {
    user_dprintf("%p", arg);

    os_printf("buf: ");
    for (; len > 0; ++buf, --len) {
        os_printf("%c", *buf);
    }
    os_printf("\n");
    // TODO
}

ICACHE_FLASH_ATTR
static void espconn_connect_cb(void *arg) {
    assert_heap();
    struct espconn *conn = arg;

    espconn_set_opt(conn, ESPCONN_REUSEADDR);
    espconn_set_opt(conn, ESPCONN_NODELAY);
    espconn_set_opt(conn, ESPCONN_KEEPALIVE);
    int keepalive_interval = 2 * 10; // 10 seconds
    espconn_set_keepalive(conn, ESPCONN_KEEPIDLE, &keepalive_interval);
    espconn_set_keepalive(conn, ESPCONN_KEEPINTVL, &keepalive_interval);
    //espconn_set_keepalive(conn, ESPCONN_KEEPCNT, 0);

    user_dprintf("connected");
    espconn_regist_disconcb(&con, espconn_disconnect_cb);
    espconn_regist_recvcb(&con, espconn_recv_cb);
    espconn_regist_sentcb(&con, espconn_sent_cb);
}

ICACHE_FLASH_ATTR
static void connect_ssl() {
    USER_INTR_LOCK();

    if (secure_connected) {
        user_dprintf("error: already connected");
        USER_INTR_UNLOCK();
        return;
    }

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
    assert_heap();

    user_dprintf("starting connection");
    assert_heap();
    assert(!secure_connected);
    sint8 rc = espconn_secure_connect(&con);
    if (rc) {
        user_dprintf("espconn_secure_connect: error %u", rc);
    } else {
        secure_connected = true;
    }
    assert_heap();
    user_dprintf("started connection: %d", rc);

    USER_INTR_UNLOCK();
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

            if (netif_default != &icmp_tap) {
                icmp_net_enslave(&icmp_config, ip_route(&event->event_info.got_ip.gw));

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

            USER_INTR_LOCK();
            if (secure_connected) {
                if (espconn_secure_disconnect(&con) != ESPCONN_OK) {
                    user_dprintf("disconnect: failed");
                }
                secure_connected = false;
            }
            USER_INTR_UNLOCK();

            if (netif_default == &icmp_tap) {
                dhcp_stop(&icmp_tap);

                icmp_net_unenslave(&icmp_config);
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

struct exc_arg {
    size_t xt_pc;
    size_t xt_ps;
    size_t xt_sar;
    size_t xt_vpri;
    size_t xt_a2;
    size_t xt_a3;
    size_t xt_a4;
    size_t xt_a5;
    size_t xt_exccause;
    size_t xt_lcount;
    size_t xt_lbeg;
    size_t xt_lend;
};

ICACHE_FLASH_ATTR
void exc_handler(struct exc_arg *exc) {
    size_t exc_cause;
    void *exc_vaddr, *sp;
    asm volatile("rsr.exccause %0" : "=r" (exc_cause));
    asm volatile("rsr.excvaddr %0" : "=r" (exc_vaddr));
    asm volatile("mov %0, a1" : "=r" (sp));

    if (exc) {
        struct exc_arg data = *exc;
        user_dprintf("Exception %d at %p", exc_cause, exc_vaddr);
        user_dprintf(
            "pc=%p ps=%p sar=%p vpri=%p a2=%p a3=%p a4=%p a5=%p exccause=%p lcount=%p lbeg=%p lend=%p",
            data.xt_pc, data.xt_ps, data.xt_sar, data.xt_vpri, data.xt_a2, data.xt_a3, data.xt_a4, data.xt_a5, data.xt_exccause, data.xt_lcount, data.xt_lbeg, data.xt_lend
        );
    }
    {
        os_printf("forward from sp=%p:", sp);
        int i;
        for (i = 0; i < 64; ++i) {
            os_printf(" %p", ((void **)sp)[i]);
        }
        os_printf("\n");
    }
    {
        os_printf("back from sp=%p:", sp);
        int i;
        for (i = 0; i < 64; ++i) {
            os_printf(" %p", ((void **)sp)[~i]);
        }
        os_printf("\n");
    }
    assert(false);
}

ICACHE_FLASH_ATTR
void user_rf_pre_init(void) {
    _xtos_set_exception_handler(9, exc_handler);
    _xtos_set_exception_handler(28, exc_handler);
    _xtos_set_exception_handler(29, exc_handler);
}

ICACHE_FLASH_ATTR
void user_init(void) {
    system_update_cpu_freq(160);
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
