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
#include "debug_esp.h"
#include "default_ca_certificate.h"
#include "connmgr.h"

static struct netif icmp_tap;
static struct icmp_net_config icmp_config;
static struct ip_info linklocal_info = {
    .ip = { IPADDR_ANY },
    .netmask = { IPADDR_ANY },
    .gw = { IPADDR_ANY },
};
bool connmgr_connected = false;
struct espconn conn;

ICACHE_FLASH_ATTR
void wifi_promiscuous_rx_cb(uint8 *buf, uint16 len) {
    register void *a0_ asm("a0");
    void *a0 = a0_;
    user_dprintf("%d @ %p", len, a0);
    return;
    print_stack();
    return;
    for (; len; ++buf, --len) {
        os_printf("%02x", *buf);
    }
    os_printf("\n");
}

ICACHE_FLASH_ATTR
static void my_wdev_go_sniffer() {
    wdev_go_sniffer();
}

ICACHE_FLASH_ATTR
static void ensure_promiscuous() {
    wifi_set_promiscuous_rx_cb(wifi_promiscuous_rx_cb);
    wDevDisableRx();
    extern char g_ic;
    char flags = 4;
    int alpha = ((int *)0x3ff1fe00)[0x26c / 4];
    char beta = ((char *)(&g_ic) + 0x180)[100];
    if (flags & 1) {
        ((int *)0x3ff1fe00)[0x26c / 4] &= ~1;
        ((int *)0x3ff1fe00)[0x26c / 4] &= ~2;
        ((int *)0x3ff1fe00)[0x26c / 4] &= ~4;
    }
    if (flags & 2) {
        ((char *)(&g_ic) + 0x180)[100] = 1;
    }
    if (flags & 4) {
        my_wdev_go_sniffer();
    }
    assert(alpha == ((int *)0x3ff1fe00)[0x26c / 4]);
    assert(beta == ((char *)(&g_ic) + 0x180)[100]);
    wDevEnableRx();
}

static void ssl_connect();
ICACHE_FLASH_ATTR
static void schedule_reconnect() {
    assert_heap();

    USER_INTR_LOCK();
    if (!connmgr_connected) {
        user_dprintf("warning: disconnect: already disconnected");
        return;
    }
    connmgr_connected = false;
    connmgr_disconnect_cb();
#ifdef DEBUG_ESP
    ssl_connect();
#else
    sys_timeout(1000, ssl_connect, NULL);
#endif
    USER_INTR_UNLOCK();
}

ICACHE_FLASH_ATTR
static void ssl_disconnect() {
    assert(connmgr_connected);
    if (espconn_secure_disconnect(&conn) != ESPCONN_OK) {
        user_dprintf("disconnect: failed");
    }
    connmgr_connected = false;
    connmgr_disconnect_cb();
}

ICACHE_FLASH_ATTR
static void espconn_reconnect_cb(void *arg, sint8 err) {
    user_dprintf("reconnect due to %d", err);

    switch (err) {
        case ESPCONN_CONN: // -11
            // We probably took too long to respond to something MAC-level
            system_restart(); // seems unrecoverable
    }

    schedule_reconnect();
}

ICACHE_FLASH_ATTR
static void espconn_disconnect_cb(void *arg) {
    schedule_reconnect();
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
    int keepalive_count = 3; // 3 * 10 s = 30 s
    espconn_set_keepalive(conn, ESPCONN_KEEPCNT, &keepalive_count);

    user_dprintf("connected");
    espconn_regist_disconcb(conn, espconn_disconnect_cb);
    espconn_regist_recvcb(conn, (espconn_recv_callback)connmgr_recv_cb);
    espconn_regist_sentcb(conn, (espconn_sent_callback)connmgr_sent_cb);

    connmgr_connect_cb(arg);
}

ICACHE_FLASH_ATTR
static void ssl_connect() {
    USER_INTR_LOCK();

    if (connmgr_connected) {
        user_dprintf("error: already connected");
        USER_INTR_UNLOCK();
        return;
    }

    os_memset(&conn, 0, sizeof(conn));
    conn.type = ESPCONN_TCP;
    conn.state = ESPCONN_NONE;
    {
        static esp_tcp tcp;
        memset(&tcp, 0, sizeof(tcp));
        tcp.remote_port = 55555;
        os_memcpy(tcp.local_ip, &icmp_tap.ip_addr, sizeof(struct ip_addr));
        os_memcpy(tcp.remote_ip, &icmp_tap.gw, sizeof(struct ip_addr));

        conn.proto.tcp = &tcp;
    }
    assert_heap();
    espconn_regist_connectcb(&conn, espconn_connect_cb);
    espconn_regist_reconcb(&conn, espconn_reconnect_cb);
    assert_heap();

    user_dprintf("starting connection");
    assert_heap();
    assert(!connmgr_connected);
    sint8 rc = espconn_secure_connect(&conn);
    if (rc) {
        user_dprintf("espconn_secure_connect: error %u", rc);
    } else {
        connmgr_connected = true;
    }
    assert_heap();
    user_dprintf("started connection: %d", rc);

    ensure_promiscuous();

    USER_INTR_UNLOCK();
}

size_t __real_ets_post(size_t a, size_t b, size_t c, size_t d);
ICACHE_FLASH_ATTR
size_t __wrap_ets_post(size_t a, size_t b, size_t c, size_t d) {
#if 0
    user_dprintf("%d", b);
    if (b == 5) {
        print_stack_once();
    } else if (b == 9) {
        print_stack_once();
    }
#endif
    return __real_ets_post(a, b, c, d);
}

size_t is_in_fiq;

void __real_wDev_ProcessFiq();
ICACHE_FLASH_ATTR
void __wrap_wDev_ProcessFiq() {
    user_dprintf("%p %p", ((void **)0x3ff20a00)[0x220 / 4], ((void **)0x3ff20a00)[0x284 / 4]);
    //size_t bit = ((size_t *)0x3ff20a00)[0x220 / 4] & (4 | 8);
    //((size_t *)0x3ff20a00)[0x220 / 4] &= ~bit;
    is_in_fiq = true;
    //ensure_promiscuous();
    __real_wDev_ProcessFiq();
    is_in_fiq = false;
    //((size_t *)0x3ff20a00)[0x220 / 4] |= bit;
}

size_t __real_lmacIsActive();
ICACHE_FLASH_ATTR
size_t __wrap_lmacIsActive() {
    register void *a0_ asm("a0");
    void *a0 = a0_;
    size_t ret = __real_lmacIsActive();
    if (is_in_fiq) {
        user_dprintf("%d @ %p", ret, a0);
    }
    return ret;
}

void __real_lmacProcessTXStartData(size_t a2);
ICACHE_FLASH_ATTR
void __wrap_lmacProcessTXStartData(size_t a2) {
    user_dprintf("%p", (void *)a2);
    __real_lmacProcessTXStartData(a2);
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
    register void *a0_ asm("a0");
    void *a0 = a0_;
    USER_INTR_LOCK();
    user_dprintf("sta_input: %p %d @ %p", m, rssi, a0);
#if 0
    print_stack_once();
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
    int ret = __real_sta_input(ni, m, rssi, nf);
    USER_INTR_UNLOCK();
    return ret;
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
                ssl_connect();
            }
            break;
        case EVENT_STAMODE_DISCONNECTED:
            user_dprintf("disconnected");

            USER_INTR_LOCK();
            if (connmgr_connected) {
                ssl_disconnect();
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

ICACHE_FLASH_ATTR
void connmgr_init() {
    user_dprintf("heap: %d", system_get_free_heap_size());
    assert_heap();

    wifi_station_set_auto_connect(0);

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

    user_dprintf("done");
    assert_heap();
}

void connmgr_start() {
    wifi_set_opmode_current(NULL_MODE);
    wifi_set_event_handler_cb(wifi_handle_event_cb);
    wifi_set_opmode_current(STATION_MODE);
    {
        struct station_config *config = (struct station_config *)os_zalloc(sizeof(struct station_config));
        const static char *ssid = "icmp-test";
        os_memcpy(config->ssid, ssid, os_strlen(ssid));
        wifi_station_set_config_current(config);
    }
    wifi_station_disconnect();
    wifi_station_connect();
    wifi_station_set_reconnect_policy(true);

    user_dprintf("started");
}

ICACHE_FLASH_ATTR
void connmgr_stop() {
    user_dprintf("heap: %d", system_get_free_heap_size());
    assert_heap();

    wifi_set_opmode_current(NULL_MODE);
    wifi_set_event_handler_cb(NULL);

    user_dprintf("stopped");
    assert_heap();
}

static X509_CTX *ca_cert = NULL;

EXP_FUNC SSL_CTX *STDCALL __real_ssl_ctx_new(uint32_t options, int num_sessions);
ICACHE_FLASH_ATTR
EXP_FUNC SSL_CTX *STDCALL __wrap_ssl_ctx_new(uint32_t options, int num_sessions) {
    options &= ~(SSL_SERVER_VERIFY_LATER | SSL_DISPLAY_CERTS | SSL_NO_DEFAULT_KEY);
    SSL_CTX *ret = __real_ssl_ctx_new(options, num_sessions);
    if (ca_cert == NULL) {
        int rc = add_cert_auth(ret, default_ca_certificate, default_ca_certificate_len);
        assert(rc == SSL_OK);
        assert(ret->ca_cert_ctx);
        assert(ret->ca_cert_ctx->cert[0] != NULL);
        ca_cert = ret->ca_cert_ctx->cert[0];
        assert(ca_cert);
    } else {
        int rc = add_cert_auth(ret, default_ca_certificate, 0);
        assert(rc == SSL_OK);
        assert(ret->ca_cert_ctx);
        assert(ret->ca_cert_ctx->cert[0] == NULL);
        ret->ca_cert_ctx->cert[0] = ca_cert;
    }
    assert(ret->ca_cert_ctx->cert[1] == NULL);
    return ret;
}

EXP_FUNC void STDCALL ICACHE_FLASH_ATTR __real_ssl_ctx_free(SSL_CTX *ssl_ctx);
ICACHE_FLASH_ATTR
EXP_FUNC void STDCALL ICACHE_FLASH_ATTR __wrap_ssl_ctx_free(SSL_CTX *ssl_ctx) {
    if (
            ca_cert != NULL &&
            ssl_ctx->ca_cert_ctx &&
            ssl_ctx->ca_cert_ctx->cert[0] == ca_cert
        ) {
        assert(ssl_ctx->ca_cert_ctx->cert[1] == NULL);
        ssl_ctx->ca_cert_ctx->cert[0] = NULL;
    }
    return __real_ssl_ctx_free(ssl_ctx);
}
