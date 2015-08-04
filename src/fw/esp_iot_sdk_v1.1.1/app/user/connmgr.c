#include "user_config.h"
#include <ets_sys.h>
#include <osapi.h>
#include <mem.h>
#include <user_interface.h>
#include <icmp_net.h>
#include <lwip/ip4.h>
#include <lwip/netif/etharp.h>
#include <lwip/sockets.h>
#include <espconn.h>
#include <debug_esp.h>
#include <default_ca_certificate.h>
#include <connmgr.h>

static struct netif icmp_tap;
static struct icmp_net_config icmp_config;
static struct ip_info linklocal_info = {
    .ip = { IPADDR_ANY },
    .netmask = { IPADDR_ANY },
    .gw = { IPADDR_ANY },
};
static uint8 last_bssid[6], sta_mac[6];
static uint8 const bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
bool connmgr_connected = false;
struct espconn conn;

static bool filter_dest = false, filter_bssid = false;

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
    user_dprintf("reconnect due to %d\x1b[35m", err);

#if 0
    switch (err) {
        case ESPCONN_CONN: // -11
            // Connection timeout
            system_restart(); // seems unrecoverable
    }
#endif

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

    user_dprintf("connected\x1b[34m");
    espconn_regist_disconcb(conn, espconn_disconnect_cb);
    espconn_regist_recvcb(conn, (espconn_recv_callback)connmgr_recv_cb);
    espconn_regist_sentcb(conn, (espconn_sent_callback)connmgr_sent_cb);

    filter_dest = filter_bssid = true;
    promisc_start();

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
        os_memset(&tcp, 0, sizeof(tcp));
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
    user_dprintf("started connection: %d\x1b[33m", rc);

    USER_INTR_UNLOCK();
}

struct sta_input_pkt {
    uint8_t pad_0_[4];
    struct {
        uint8_t pad_0_[4];
        uint8_t *payload;
    } *packet;
    uint8_t pad_8_[20 - 8];
    short header_len;
    short body_len;
    // byte 24
};

int __real_sta_input(void *ni, struct sta_input_pkt *m, int rssi, int nf);
ICACHE_FLASH_ATTR
int __wrap_sta_input(void *ni, struct sta_input_pkt *m, int rssi, int nf) {
    if (m->header_len >= 22) {
        assert(nf == 0);
        assert(m->packet->payload == ((uint8_t ***)m)[1][1]);
        assert(m->header_len == (int)((short *)m)[10]);
        assert(m->body_len == (int)((short *)m)[11]);
        connmgr_packet_cb(m->packet->payload, m->header_len, m->body_len, rssi);

        if (
                filter_dest && (
                    memcmp(bcast_mac, m->packet->payload + 4, 6) &&
                    memcmp(sta_mac, m->packet->payload + 4, 6)
                ) ||
                filter_bssid && (
                    memcmp(last_bssid, m->packet->payload + 10, 6) ||
                    memcmp(last_bssid, m->packet->payload + 16, 6)
                )
            ) {
            ppRecycleRxPkt(m);
            return ERR_OK;
        }
    }

    return __real_sta_input(ni, m, rssi, nf);
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
                netif_set_down(&icmp_tap);

                icmp_net_unenslave(&icmp_config);
                netif_default = saved_default;
                saved_default = NULL;
            }
            filter_bssid = false;
            filter_dest = true;
            break;
        case EVENT_STAMODE_CONNECTED:
            user_dprintf("connected\x1b[32m");
            os_memcpy(last_bssid, event->event_info.connected.bssid, sizeof(last_bssid));
            wifi_get_macaddr(STATION_IF, sta_mac);
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

    icmp_config.relay_ip.addr = ipaddr_addr("54.191.1.223");

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

    user_dprintf("started\x1b[31m");
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
