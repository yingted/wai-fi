#include <user_config.h>
#include <ets_sys.h>
#include <osapi.h>
#include <mem.h>
#include <user_interface.h>
#include <icmp_net.h>
#include <lwip/ip4.h>
#include <lwip/netif/etharp.h>
#include <lwip/sockets.h>
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
bool connmgr_connected = true; // set to false in connmgr_init
static SSL_CTX *ssl_ctx = NULL;
static SSL *ssl = NULL;
static struct tcp_pcb *ssl_pcb = NULL;

static bool filter_dest = false, filter_bssid = false;

static void ssl_connect();
static void ssl_disconnect();

// State management

/**
 * Update the connection watchdog.
 * This function is always called within the lock.
 */
ICACHE_FLASH_ATTR
static void connmgr_set_connected(bool new_connected) {
    if (connmgr_connected == new_connected) {
        return;
    }
    connmgr_connected = new_connected;
    static os_timer_t watchdog;
    if (new_connected) {
        os_timer_disarm(&watchdog);
    } else {
        os_timer_setfn(&watchdog, system_restart, NULL);
        os_timer_arm(&watchdog, 1000 * 60 * 5 /* minutes */, 0);
    }
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

// Initialization

ICACHE_FLASH_ATTR
void connmgr_init() {
    user_dprintf("heap: %d", system_get_free_heap_size());
    assert_heap();
    connmgr_set_connected(false);

    wifi_station_set_auto_connect(0);

    // XXX session caching
    ssl_ctx = ssl_ctx_new(SSL_CONNECT_IN_PARTS, 0);
    err_t rc = add_cert_auth(ssl_ctx, default_ca_certificate, default_ca_certificate_len);
    assert(rc == SSL_OK);
    assert(ret->ca_cert_ctx);
    assert(ret->ca_cert_ctx->cert[0] != NULL);
    assert(ret->ca_cert_ctx->cert[1] == NULL);

    //icmp_config.relay_ip.addr = ipaddr_addr("54.191.1.223");
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
        const static char *ssid = "uw-wifi-setup-no-encryption";
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

// SSL client

ICACHE_FLASH_ATTR
static void schedule_reconnect() {
    debug_esp_assert_not_nmi();
    assert_heap();

    USER_INTR_LOCK();
    if (!connmgr_connected) {
        user_dprintf("warning: disconnect: already disconnected");
        return;
    }
    connmgr_set_connected(false);
    connmgr_disconnect_cb();
#ifdef DEBUG_ESP
    ssl_connect();
#else
    sys_timeout(10000, ssl_connect, NULL);
#endif
    USER_INTR_UNLOCK();
}

ICACHE_FLASH_ATTR
static void ssl_disconnect() {
    assert(connmgr_connected);
    assert(ssl != NULL);
    ssl_free(ssl);
    tcp_abort(ssl_pcb);
    connmgr_set_connected(false);
    connmgr_disconnect_cb();
}

ICACHE_FLASH_ATTR
void ssl_pcb_err_cb(void *arg, err_t err) {
    debug_esp_assert_not_nmi(); // should fail
    user_dprintf("reconnect due to %d\x1b[35m", err);
    ssl_pcb = NULL;
    connmgr_set_connected(false);
    connmgr_disconnect_cb();
    schedule_reconnect();
}

ICACHE_FLASH_ATTR
err_t ssl_pcb_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
    assert(err == ERR_OK);
    user_dprintf("tcp connected: err=%d", err);
    ssl = SSLClient_new(ssl_ctx, ssl_pcb, NULL, 0);
    return ERR_OK;
}

ICACHE_FLASH_ATTR
err_t ssl_pcb_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (err != ERR_OK) {
        user_dprintf("err=%d", err);
        assert(false);
    }

#if 0
    USER_INTR_LOCK();
    connmgr_set_connected(true);
    USER_INTR_UNLOCK();

    user_dprintf("connected\x1b[34m");
    filter_dest = filter_bssid = true;
    promisc_start();
    connmgr_connect_cb(tpcb);
#endif
    return err;
}

ICACHE_FLASH_ATTR
err_t ssl_pcb_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    connmgr_sent_cb(tpcb, len);
    return ERR_OK;
}

ICACHE_FLASH_ATTR
err_t ssl_pcb_poll_cb(void *arg, struct tcp_pcb *tpcb) {
    //XXX
    return ERR_OK;
}

ICACHE_FLASH_ATTR
static void ssl_connect() {
    USER_INTR_LOCK();

    if (connmgr_connected) {
        user_dprintf("error: already connected");
        USER_INTR_UNLOCK();
        return;
    }

    assert(ssl_pcb == NULL);
    ssl_pcb = tcp_new();
    assert(ssl_pcb != NULL);
    ip_set_option(ssl_pcb, SO_REUSEADDR);
    tcp_nagle_disable(ssl_pcb);
    ssl_pcb->so_options |= SOF_KEEPALIVE;
    ssl_pcb->keep_idle = 1000 * 10 /* seconds */;
    ssl_pcb->keep_intvl = 1000 * 5 /* seconds */;
    ssl_pcb->keep_cnt = 5; // (10 seconds) + (5 - 1) * (5 seconds) = (30 seconds)

    if (err_t rc = tcp_bind(ssl_pcb, &icmp_tap.ip_addr, 0)) {
        user_dprintf("tcp_bind: error %d", rc);
        assert(false);
        system_restart();
    }

    tcp_err(ssl_pcb, ssl_pcb_err_cb);
    tcp_recv(ssl_pcb, ssl_pcb_recv_cb);
    tcp_sent(ssl_pcb, ssl_pcb_sent_cb);
    // tcp_poll(ssl_pcb, ssl_pcb_poll_cb, 5 /* seconds */ * 1000 / 500);

    if (err_t rc = tcp_connect(ssl_pcb, &icmp_tap.gw, 55555, ssl_pcb_connected_cb)) {
        user_dprintf("tcp_connect: error %d", rc);
        assert(false);
        system_restart();
    }

    assert(!connmgr_connected);
    connmgr_set_connected(true);
    assert_heap();

    USER_INTR_UNLOCK();
}
