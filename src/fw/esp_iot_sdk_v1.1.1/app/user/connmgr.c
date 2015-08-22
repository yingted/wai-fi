#include <user_config.h>
#include <ets_sys.h>
#include <osapi.h>
#include <mem.h>
#include <user_interface.h>
#include <icmp_net.h>
#include <lwip/ip4.h>
#include <lwip/netif/etharp.h>
#include <lwip/sockets.h>
#include <lwip/tcp.h>
#include <lwip/timers.h>
#include <debug_esp.h>
#include <default_ca_certificate.h>
#include <promisc.h>
#include <connmgr.h>
#include <coro.h>

// Network config. May need to be exported later.
static struct netif icmp_tap;
static struct icmp_net_config icmp_config;
static struct ip_info linklocal_info = {
    .ip = { IPADDR_ANY },
    .netmask = { IPADDR_ANY },
    .gw = { IPADDR_ANY },
};

// Stuff we can't pass via coro.
static uint8 last_bssid[6], sta_mac[6];
static uint8 const bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static struct ip_addr ap_gw_addr;

// Receive buffer
static struct pbuf *ssl_pcb_recv_buf = NULL;

// MAC filter flags
static bool filter_dest = false, filter_bssid = false;

// Coroutine stack
static CORO_T(256) coro;
// Coroutine decls
extern int os_port_impure_errno;
void wifi_handle_event_cb(System_Event_t *event);
static void ssl_pcb_err_cb(void *arg, err_t err);
static err_t ssl_pcb_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err);
static err_t ssl_pcb_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t ssl_pcb_poll_cb(void *arg, struct tcp_pcb *tpcb);
static err_t ssl_pcb_sent_cb(void * arg, struct tcp_pcb * tpcb, u16_t len);
static void connmgr_timer(void *arg);
static void connmgr_restart(void *arg);

#define EVENT_ABORT        0x00000001 // remote closed SSL connection
#define EVENT_START        0x00000002 // client called connmgr_start
#define EVENT_STOP         0x00000004 // client called connmgr_stop
#define EVENT_GOT_IP       0x00000008 // AP set DHCP ACK
#define EVENT_CONNECT      0x00000010 // remote sent syn/ack
#define EVENT_POLL         0x00000020 // connection idle or remote sent ack
#define EVENT_IDLE         0x00000040 // idle (remote may have sent data)
#define EVENT_TIMER        0x00000080 // timer went off
#define EVENT_DISASSOCIATE 0x00000100 // AP sent disassociate
#define EVENT_ANY ((size_t)~0)
#define EVENT_INTR (EVENT_ABORT | EVENT_DISASSOCIATE | EVENT_STOP)

#define CORO_IF(event_name) \
    CORO_YIELD(coro, EVENT_ANY); \
    _Static_assert(!(EVENT_INTR & EVENT_ ## event_name), "Cannot wait for any interruption"); \
    assert(coro.ctrl.event & (EVENT_INTR | EVENT_ ## event_name | EVENT_POLL)); \
    if (!(coro.ctrl.event & EVENT_INTR))

// State management

ICACHE_FLASH_ATTR
static void connmgr_init_impl(void *arg) {
    user_dprintf("heap: %d", system_get_free_heap_size());
    assert_heap();
    sys_timeout(5 /* minutes */ * 60 * 1000, connmgr_restart, NULL);

    wifi_station_set_auto_connect(0);

    // XXX session caching
    static SSL_CTX *ssl_ctx;
    ssl_ctx = ssl_ctx_new(0, 0);
    {
        err_t rc = add_cert_auth(ssl_ctx, default_ca_certificate, default_ca_certificate_len);
        assert(rc == SSL_OK);
    }
    assert(ssl_ctx->ca_cert_ctx);
    assert(ssl_ctx->ca_cert_ctx->cert[0] != NULL);
    assert(ssl_ctx->ca_cert_ctx->cert[1] == NULL);

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

    for (;;) {
        CORO_IF(START) {
connmgr_start_resume:;
            wifi_set_opmode_current(NULL_MODE);
            wifi_set_event_handler_cb(wifi_handle_event_cb);
            wifi_set_opmode_current(STATION_MODE);
            {
                static struct station_config config; // 0-initialized
                const static char *const ssid = "uw-wifi-setup-no-encryption";
                os_memcpy(config.ssid, ssid, os_strlen(ssid));
                wifi_station_set_config_current(&config);
            }
            wifi_station_disconnect();
            wifi_station_connect();
            wifi_station_set_reconnect_policy(true);

            user_dprintf("started\x1b[31m");

            CORO_IF(GOT_IP) {
                assert_heap();
                static struct netif *saved_default = NULL;
                {
                    assert(netif_default != &icmp_tap);
                    icmp_net_enslave(&icmp_config, ip_route(&ap_gw_addr));

                    assert(saved_default == NULL);
                    saved_default = netif_default;
                    netif_default = &icmp_tap;

                    err_t rc = dhcp_start(&icmp_tap);
                    if (rc != ERR_OK) {
                        user_dprintf("dhcp error: %d", rc);
                    }
                }

                CORO_IF(GOT_IP) {
                    assert(netif_default == &icmp_tap);
                    user_dprintf("tunnel established");

                    for (;;) {
                        USER_INTR_LOCK();
                        static struct tcp_pcb *ssl_pcb;
                        ssl_pcb = tcp_new();
                        assert(ssl_pcb != NULL);
                        ip_set_option(ssl_pcb, SO_REUSEADDR);
                        tcp_nagle_disable(ssl_pcb);
                        ssl_pcb->so_options |= SOF_KEEPALIVE;
                        ssl_pcb->keep_idle = 1000 * 10 /* seconds */;
                        ssl_pcb->keep_intvl = 1000 * 5 /* seconds */;
                        ssl_pcb->keep_cnt = 5; // (10 seconds) + (5 - 1) * (5 seconds) = (30 seconds)

                        err_t rc;
                        if ((rc = tcp_bind(ssl_pcb, &icmp_tap.ip_addr, 0))) {
                            user_dprintf("tcp_bind: error %d", rc);
                            assert(false);
                            system_restart();
                        }

                        tcp_err(ssl_pcb, ssl_pcb_err_cb);
                        tcp_recv(ssl_pcb, ssl_pcb_recv_cb);
                        tcp_sent(ssl_pcb, ssl_pcb_sent_cb);
                        tcp_poll(ssl_pcb, ssl_pcb_poll_cb, 5 /* seconds */ * 1000 / 500);

                        if ((rc = tcp_connect(ssl_pcb, &icmp_tap.gw, 55555, ssl_pcb_connected_cb))) {
                            user_dprintf("tcp_connect: error %d", rc);
                            assert(false);
                            system_restart();
                        }

                        assert_heap();
                        USER_INTR_UNLOCK();

                        CORO_IF(CONNECT) {
                            static SSL *ssl;
                            ssl = ssl_client_new(ssl_ctx, (int)ssl_pcb, NULL, 0);

                            sys_untimeout(connmgr_restart, NULL);
                            user_dprintf("connected\x1b[34m");
                            filter_dest = filter_bssid = true;
                            promisc_start();

                            connmgr_worker(ssl);

                            sys_timeout(5 /* minutes */ * 60 * 1000, connmgr_restart, NULL);
                            ssl_free(ssl);
                        }

                        assert(ssl_pcb != NULL);
                        tcp_abort(ssl_pcb);
                        ssl_pcb = NULL;

                        if (coro.ctrl.event == EVENT_ABORT) {
                            // We've handled the ABORT. Wait 10 seconds.
                            sys_timeout(10 /* seconds */ * 1000, connmgr_timer, NULL);
                            CORO_IF(TIMER) {
                                continue;
                            } else {
                                sys_untimeout(connmgr_timer, NULL);
                            }
                        } else {
                            // We haven't handled it.
                            break;
                        }
                    }
                }

                {
                    assert(netif_default == &icmp_tap);

                    dhcp_stop(&icmp_tap);
                    netif_set_down(&icmp_tap);

                    icmp_net_unenslave(&icmp_config);
                    netif_default = saved_default;
                    saved_default = NULL;
                }
            }

            user_dprintf("heap: %d", system_get_free_heap_size());
            assert_heap();

            wifi_set_opmode_current(NULL_MODE);
            wifi_set_event_handler_cb(NULL);
            filter_bssid = false;
            filter_dest = true;
            user_dprintf("disassociated");

            if (coro.ctrl.event & EVENT_DISASSOCIATE) {
                // We've handled the dissassociation. Wait 10 seconds.
                sys_timeout(10 /* seconds */ * 1000, connmgr_timer, NULL);
                CORO_IF(TIMER) {
                    goto connmgr_start_resume;
                } else {
                    sys_untimeout(connmgr_timer, NULL);
                }
            }

            assert_heap();
        } else {
            assert(false);
        }

        assert(coro.ctrl.event & EVENT_STOP);

        // Only stop logging after connmgr_stop()
        wifi_promiscuous_enable(0);
        user_dprintf("stopped");
    }
}

// Async client APIs

ICACHE_FLASH_ATTR
void connmgr_init() {
    CORO_START(coro, connmgr_init_impl, NULL);
}

ICACHE_FLASH_ATTR
void connmgr_start() {
    CORO_RESUME(coro, EVENT_START);
}

ICACHE_FLASH_ATTR
void connmgr_stop() {
    CORO_RESUME(coro, EVENT_STOP);
}

// Callbacks for library code

ICACHE_FLASH_ATTR
void wifi_handle_event_cb(System_Event_t *event) {
    switch (event->event) {
        case EVENT_STAMODE_GOT_IP:
            user_dprintf("ip " IPSTR " mask " IPSTR " gw " IPSTR,
                      IP2STR(&event->event_info.got_ip.ip),
                      IP2STR(&event->event_info.got_ip.mask),
                      IP2STR(&event->event_info.got_ip.gw));
            if (false) {
                ap_gw_addr = event->event_info.got_ip.gw;
            }
            os_memcpy(&ap_gw_addr, &event->event_info.got_ip.gw, sizeof(ap_gw_addr));
            assert_heap();

            debug_esp_assert_not_nmi();
            CORO_RESUME(coro, EVENT_GOT_IP);
            break;
        case EVENT_STAMODE_DISCONNECTED:
            user_dprintf("disconnected");
            CORO_RESUME(coro, EVENT_DISASSOCIATE);
            break;
        case EVENT_STAMODE_CONNECTED:
            // We handle this in GOT_IP anyways, so just grab the SSID.
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
static void ssl_pcb_err_cb(void *arg, err_t err) {
    debug_esp_assert_not_nmi();
    user_dprintf("reconnect due to %d\x1b[35m", err);
    CORO_RESUME(coro, EVENT_ABORT);
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
    user_dprintf("tcp connected: err=%d", err);
    assert(err == ERR_OK);
    CORO_RESUME(coro, EVENT_CONNECT);
    return ERR_OK;
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    user_dprintf("%p", p);
    if (p == NULL) {
        user_dprintf("err=%d", err);
        return ERR_OK;
    }
    if (err != ERR_OK) {
        user_dprintf("err=%d", err);
        assert(false);
    }

    if (ssl_pcb_recv_buf == NULL) {
        ssl_pcb_recv_buf = p;
    } else {
        pbuf_cat(ssl_pcb_recv_buf, p);
        // We'll send EVENT_IDLE in icmp_net_process_queued_pbufs_callback.
        // That way we'll be out of lwIP.
    }
    return err;
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_poll_cb(void *arg, struct tcp_pcb *tpcb) {
    user_dprintf("");
    CORO_RESUME(coro, EVENT_POLL);
    return ERR_OK;
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_sent_cb(void * arg, struct tcp_pcb * tpcb, u16_t len) {
    user_dprintf("");
    return ssl_pcb_poll_cb(arg, tpcb);
}

ICACHE_FLASH_ATTR
void icmp_net_process_queued_pbufs_callback() {
    user_dprintf("");
    CORO_RESUME(coro, EVENT_IDLE);
}

ICACHE_FLASH_ATTR
static void connmgr_timer(void *arg) {
    CORO_RESUME(coro, EVENT_TIMER);
}

ICACHE_FLASH_ATTR
static void connmgr_restart(void *arg) {
    system_restart();
}

// Blocking socket implementation

#define CONNMGR_TESTCANCEL() \
    if (coro.ctrl.event & EVENT_INTR) { \
        os_port_impure_errno = EIO; \
        return -1; \
    }

__attribute__((used))
ICACHE_FLASH_ATTR
ssize_t os_port_socket_read(int fd, void *buf, size_t len) {
    assert(len > 0);
    user_dprintf("%p %d", buf, len);
    CONNMGR_TESTCANCEL();
    // Read from the linked list.
    for (;;) {
        // Try to read read_len from the buffer.
        u16_t read_len = ssl_pcb_recv_buf->len;
        if (read_len > len) {
            // Read < 1 pbuf. Read was satisfied. Don't bother updating buffer pointers.
            memcpy(buf, ssl_pcb_recv_buf->payload, len);
            break;
        }
        // Read >= 1 pbuf. Update pointers.
        memcpy(buf, ssl_pcb_recv_buf->payload, read_len);
        *(char **)&buf += read_len;
        len -= read_len;

        // Free the pbuf.
        struct pbuf *prev_pbuf = ssl_pcb_recv_buf;
        ssl_pcb_recv_buf = prev_pbuf->next;
        while (ssl_pcb_recv_buf == NULL) {
            CORO_YIELD(coro, EVENT_IDLE);
            CONNMGR_TESTCANCEL();
        }
        pbuf_ref(ssl_pcb_recv_buf);
        pbuf_dechain(prev_pbuf);
        pbuf_free(prev_pbuf);
    }

    return len;
}

__attribute__((used))
ICACHE_FLASH_ATTR
ssize_t os_port_socket_write(int fd, const void *volatile buf, volatile size_t len) {
    struct tcp_pcb *volatile tpcb = (struct tcp_pcb *)fd;
    user_dprintf("%p %d", buf, len);
    CONNMGR_TESTCANCEL();
    for (;;) {
        err_t rc = tcp_write(tpcb, buf, len, 0);
        switch (rc) {
            case ERR_OK:
                return len;
            case ERR_MEM:
                // We need to poll until we can write.
                CORO_YIELD(coro, EVENT_POLL);
                CONNMGR_TESTCANCEL();
                continue;
            default:;
                os_port_impure_errno = rc;
                return -1;
        }
    }
    return len;
}

// API hooks

void __real_tcp_tmr(void);
ICACHE_FLASH_ATTR
void __wrap_tcp_tmr(void) {
    // TODO investigate this
#if 0
    {
        static size_t last_time, sys_last_time;
        size_t time = system_get_time(), sys_time = NOW()/(TIMER_CLK_FREQ/1000);
        user_dprintf("delay=%d, sys_delay=%d", time - last_time, sys_time - sys_last_time);
        if (last_time != 0 && time - last_time < 124000) {
            //gdb_stub_break();
        }
        //gdb_stub_break();
        last_time = time;
        sys_last_time = sys_time;
    }
#endif
    static bool has_run = false;
    static size_t last_time;
    size_t time = system_get_time();
    if ((time - last_time < (TCP_TMR_INTERVAL * 3 / 4) * 1000) && has_run) {
        return;
    }
    last_time = time;
    has_run = true;
    __real_tcp_tmr();
}

// TODO remove after debugging "double timer"
void __real_tcp_timer_needed(void);
ICACHE_FLASH_ATTR
void __wrap_tcp_timer_needed(void) {
    static size_t enter_count = 0;
    assert(enter_count++ == 0);
    //user_dprintf("");
    __real_tcp_timer_needed();
    assert(--enter_count == 0);
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

/**
 * Capture all packets. Send them to connmgr_packet_cb.
 */
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
                (filter_dest && (
                    memcmp(bcast_mac, m->packet->payload + 4, 6) &&
                    memcmp(sta_mac, m->packet->payload + 4, 6)
                )) ||
                (filter_bssid && (
                    memcmp(last_bssid, m->packet->payload + 10, 6) ||
                    memcmp(last_bssid, m->packet->payload + 16, 6)
                ))
            ) {
            ppRecycleRxPkt(m);
            return ERR_OK;
        }
    }

    return __real_sta_input(ni, m, rssi, nf);
}
