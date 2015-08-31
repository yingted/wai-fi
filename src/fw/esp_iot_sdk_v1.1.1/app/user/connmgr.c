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
static struct tcp_pcb *ssl_pcb = NULL;
static SSL *ssl = NULL;
static struct pbuf *write_head = NULL;

// Receive buffer
static struct pbuf *ssl_pcb_recv_buf = NULL;

// MAC filter flags
static bool filter_dest = false, filter_bssid = false;

static coro_t coro;
static size_t coro_interrupt_later = 0;
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

static bool restart_scheduled = false;
#define SCHEDULE_RESTART() \
    do { \
        if (!restart_scheduled) { \
            sys_timeout(5 /* minutes */ * 60 * 1000, connmgr_restart, NULL); \
            restart_scheduled = true; \
        } \
    } while (0)
#define UNSCHEDULE_RESTART() \
    do { \
        if (restart_scheduled) { \
            restart_scheduled = false; \
            sys_untimeout(connmgr_restart, NULL); \
        } \
    } while (0)

#define EVENT_ABORT        0x00000001 // remote closed SSL connection
#define EVENT_START        0x00000002 // client called connmgr_start
#define EVENT_STOP         0x00000004 // client called connmgr_stop
#define EVENT_GOT_IP       0x00000008 // AP set DHCP ACK
#define EVENT_CONNECT      0x00000010 // remote sent syn/ack
#define EVENT_POLL         0x00000020 // connection idle (every 5 seconds after) or remote sent ack
#define EVENT_IDLE         0x00000040 // connection just went idle (remote may have sent data)
#define EVENT_TIMER        0x00000080 // timer went off
#define EVENT_DISASSOCIATE 0x00000100 // AP sent disassociate
#define EVENT_ANY ((size_t)~0)
#define EVENT_INTR (EVENT_ABORT | EVENT_DISASSOCIATE | EVENT_STOP) // events that interrupt operations
#define EVENT_IGNORE (EVENT_POLL | EVENT_IDLE) // events that can be ignored

#define CORO_IF(event_name) \
    user_dprintf("CORO_IF(" # event_name ") <yield>"); \
    if (coro_interrupt_later) { \
        coro.event = coro_interrupt_later; \
        coro_interrupt_later = 0; \
    } else { \
        _Static_assert(!(EVENT_INTR & EVENT_ ## event_name), "Cannot wait for any interruption"); \
        CORO_YIELD(coro, EVENT_INTR | EVENT_ ## event_name); /* may ignore non-ignorable events */ \
    } \
    if (!(coro.event & EVENT_INTR)) \
        user_dprintf("CORO_IF(" # event_name ") <resume>"); \
    else \
        user_dprintf("CORO_IF(" # event_name ") <interrupt>"); \
    assert(coro.state == CORO_RESUME); \
    if (!(coro.event & EVENT_INTR))

#define CORO_INTERRUPTED(coro) \
    (coro ## _interrupt_later || (coro.event & EVENT_INTR))

#define CORO_INTERRUPT(coro, what) \
    _Static_assert(what & EVENT_INTR, "Passed non-interrupt to CORO_INTERRUPT"); \
    if (coro.state == CORO_YIELD) \
        CORO_RESUME(coro, what); \
    else \
        coro_interrupt_later = what;

#define CORO_HANDLE_ALL(coro, what) \
    assert(coro.event == what); \
    if (coro_interrupt_later == what) \
        coro_interrupt_later = 0;

// State management

ICACHE_FLASH_ATTR
static void connmgr_init_impl() {
    CORO_BEGIN();

    user_dprintf("heap: %d", system_get_free_heap_size());
    assert_heap();
    SCHEDULE_RESTART();

    wifi_station_set_auto_connect(0);

    // TODO session caching?
    static SSL_CTX *ssl_ctx;
    ssl_ctx = ssl_ctx_new(SSL_CONNECT_IN_PARTS, 0);
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

    user_dprintf("startup finished");
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
                    assert(ip_route(&ap_gw_addr) != NULL);
                    icmp_net_enslave(&icmp_config, ip_route(&ap_gw_addr));

                    assert(saved_default == NULL);
                    saved_default = netif_default;
                    netif_default = &icmp_tap;

                    {
                        err_t rc = dhcp_start(&icmp_tap);
                        if (rc != ERR_OK) {
                            user_dprintf("dhcp error: %d", rc);
                        }
                    }
                }

                user_dprintf("establishing tunnel");

                CORO_IF(GOT_IP) {
                    assert(netif_default == &icmp_tap);
                    user_dprintf("tunnel established");

                    for (;;) {
                        USER_INTR_LOCK();
                        assert(ssl_pcb == NULL);
                        ssl_pcb = tcp_new();
                        assert(ssl_pcb != NULL);
                        ip_set_option(ssl_pcb, SO_REUSEADDR);
                        tcp_nagle_disable(ssl_pcb);
                        ip_set_option(ssl_pcb, SO_KEEPALIVE);
                        {
                            // Field manipulation
                            struct my_tcp_pcb *pcb = (struct my_tcp_pcb *)ssl_pcb;
                            // IPv4 stuff is all right
                            _Static_assert(offsetof(struct my_tcp_pcb, local_ip) == 0, "Not ABI compatible");
                            _Static_assert(offsetof(struct my_tcp_pcb, remote_ip) == 4, "Not ABI compatible");
                            _Static_assert(offsetof(struct my_tcp_pcb, so_options) == 8, "Not ABI compatible");
                            _Static_assert(offsetof(struct my_tcp_pcb, tos) == 9, "Not ABI compatible");
                            _Static_assert(offsetof(struct my_tcp_pcb, ttl) == 10, "Not ABI compatible");
                            // TCP stuff is almost completely broken. Not even going to try to list all of it.
                            _Static_assert(offsetof(struct my_tcp_pcb, next) == 12, "Not ABI compatible");
                            _Static_assert(offsetof(struct my_tcp_pcb, prio) == 20, "Not ABI compatible"); // 28 by default
                            _Static_assert(offsetof(struct my_tcp_pcb, callback_arg) == 24, "Not ABI compatible"); // 16 by default
                            _Static_assert(offsetof(struct my_tcp_pcb, mss) == 60, "Not ABI compatible"); // 58 by default
                            _Static_assert(offsetof(struct my_tcp_pcb, errf) == 148, "Not ABI compatible"); // 140 by default
                            _Static_assert(sizeof(struct my_tcp_pcb) >= 170, "Not ABI compatible");

                            _Static_assert(offsetof(struct my_tcp_pcb, keep_idle) == 152, "Not ABI compatible");
                            pcb->keep_idle = 1000 * 10 /* seconds */; // 2 minutes by default
                            _Static_assert(offsetof(struct my_tcp_pcb, keep_intvl) == 156, "Not ABI compatible");
                            pcb->keep_intvl = 1000 * 5 /* seconds */; // 10 seconds by default
                            _Static_assert(offsetof(struct my_tcp_pcb, keep_cnt) == 160, "Not ABI compatible");
                            // (10 seconds) + (5 - 1) * (5 seconds) = (30 seconds)
                            pcb->keep_cnt = 5; // 9 by default
                        }

                        {
                            err_t rc;
                            if ((rc = tcp_bind(ssl_pcb, &icmp_tap.ip_addr, 0))) {
                                user_dprintf("tcp_bind: error %d", rc);
                                assert(false);
                                system_restart();
                            }
                        }

                        tcp_err(ssl_pcb, ssl_pcb_err_cb);
                        tcp_recv(ssl_pcb, ssl_pcb_recv_cb);
                        tcp_sent(ssl_pcb, ssl_pcb_sent_cb);
                        tcp_poll(ssl_pcb, ssl_pcb_poll_cb, 5 /* seconds */ * 1000 / 500);

                        {
                            err_t rc;
                            if ((rc = tcp_connect(ssl_pcb, &icmp_tap.gw, 55555, ssl_pcb_connected_cb))) {
                                user_dprintf("tcp_connect: error %d", rc);
                                assert(false);
                                system_restart();
                            }
                        }

                        assert_heap();
                        USER_INTR_UNLOCK();

                        CORO_IF(CONNECT) {
                            assert(ssl == NULL);
                            ssl = ssl_client_new(ssl_ctx, (int)ssl_pcb, NULL, 0);
                            assert(ssl != NULL);

                            user_dprintf("starting handshake");
                            {
                                static int status;
                                status = SSL_OK;
                                os_port_impure_errno = 0;
                                while (ssl->hs_status != SSL_OK) {
                                    status = ssl_read(ssl, NULL);
                                    if (status < SSL_OK) {
                                        break;
                                    }
                                    if (status == SSL_OK && os_port_impure_errno == EAGAIN) {
                                        CORO_IF(IDLE) {
                                            continue;
                                        } else {
                                            // We got some sort of error.
                                            status = SSL_ERROR_DEAD;
                                            break;
                                        }
                                    }
                                }
                                ssl->hs_status = status;
                            }

                            user_dprintf("handshake status: %d", ssl_handshake_status(ssl));
                            if (ssl_handshake_status(ssl) != SSL_OK) {
                                user_dprintf("handshake failed");
                                coro.event = EVENT_ABORT;
                            } else {
                                UNSCHEDULE_RESTART();
                                user_dprintf("connected\x1b[34m");
                                filter_dest = filter_bssid = true;
                                promisc_start();

                                for (;;) {
                                    // Read all we can
                                    for (;;) {
                                        uint8_t *dst = NULL;
                                        int rc = ssl_read(ssl, &dst);
                                        if (rc < SSL_OK) {
                                            // Send ourselves an event
                                            user_dprintf("ssl_read returned %d", rc);
                                            coro.event = EVENT_ABORT;
                                            goto abort_ssl;
                                        }
                                        if (dst == NULL) {
                                            assert(rc == 0);
                                            break; // No record
                                        }
                                        assert(rc > 0);
                                        connmgr_record_cb(ssl, dst, rc); // could block
                                    }

                                    // Do any writes in connmgr_idle_cb
                                    if (IS_SET_SSL_FLAG(SSL_NEED_RECORD)) {
                                        connmgr_idle_cb(ssl);
                                        while (write_head != NULL && !CORO_INTERRUPTED(coro)) {
                                            assert(ssl_pcb != NULL);
                                            static struct pbuf *to_send;

                                            to_send = write_head;
                                            pbuf_ref(write_head = to_send->next);
                                            pbuf_dechain(to_send);
                                            assert(to_send->len <= RT_MAX_PLAIN_LENGTH);

                                            os_port_impure_errno = 0;
                                            int rc = send_packet(ssl, PT_APP_PROTOCOL_DATA, to_send->payload, to_send->len);
                                            if (rc == SSL_ERROR_CONN_LOST && os_port_impure_errno == EBUSY) {
                                                // We're in the middle of writing. If we can't write, we're dead.
                                                SCHEDULE_RESTART();
                                                user_dprintf("waiting until writing is possible\x1b[36m");
                                                do {
                                                    CORO_IF(POLL) {
                                                        os_port_impure_errno = 0;
                                                        rc = send_raw_packet(ssl, PT_APP_PROTOCOL_DATA);
                                                    } else {
                                                        rc = SSL_ERROR_CONN_LOST; // restore the local
                                                        break; // couldn't handle the connection lost error
                                                    }
                                                } while (rc == SSL_ERROR_CONN_LOST && os_port_impure_errno == EBUSY);

                                                if (rc != SSL_ERROR_CONN_LOST) {
                                                    UNSCHEDULE_RESTART();
                                                    user_dprintf("reconnected\x1b[34m");
                                                }
                                            }

                                            pbuf_free(to_send);

                                            if (rc < 0) {
                                                // Send ourselves an event
                                                user_dprintf("send_raw_packet returned %d", rc);
                                                coro.event = EVENT_ABORT;
                                                goto abort_ssl;
                                            }
                                        }
                                        if (!CORO_INTERRUPTED(coro)) {
                                            assert(ssl_pcb != NULL);
                                            tcp_output(ssl_pcb);
                                        }
                                    }

                                    CORO_IF(IDLE) {
                                        continue;
                                    } else {
                                        break;
                                    }
                                }
                            }
abort_ssl:;

                            user_dprintf("aborting ssl");
                            SCHEDULE_RESTART();
                            assert(ssl != NULL);
                            ssl_free(ssl);
                            ssl = NULL;
                            if (write_head != NULL) {
                                pbuf_free(write_head);
                                write_head = NULL;
                            }
                        }

                        user_dprintf("aborting ssl_pcb");
                        assert(coro.state == CORO_RESUME);
                        if (ssl_pcb != NULL) {
                            tcp_abort(ssl_pcb);
                            USER_INTR_LOCK();
                            if (ssl_pcb_recv_buf != NULL) {
                                pbuf_free(ssl_pcb_recv_buf);
                                ssl_pcb_recv_buf = NULL;
                            }
                            USER_INTR_UNLOCK();
                        }

                        if (coro.event == EVENT_ABORT) {
                            CORO_HANDLE_ALL(coro, EVENT_ABORT);
                            // We've handled the ABORT. Wait 10 seconds.
                            user_dprintf("reconnecting in 10 seconds");
                            sys_timeout(10 /* seconds */ * 1000, connmgr_timer, NULL);
                            CORO_IF(TIMER) {
                                continue;
                            } else {
                                sys_untimeout(connmgr_timer, NULL);
                                break;
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

            if (coro.event == EVENT_DISASSOCIATE) {
                CORO_HANDLE_ALL(coro, EVENT_DISASSOCIATE);
                // We've handled the dissassociation. Wait 10 seconds.
                user_dprintf("reassociating in 10 seconds");
                sys_timeout(10 /* seconds */ * 1000, connmgr_timer, NULL);
                CORO_IF(TIMER) {
                    // Do nothing.
                } else {
                    sys_untimeout(connmgr_timer, NULL);
                }
                // Never synthesize a STOP event.
                goto connmgr_start_resume;
            }

            assert_heap();
        } else {
            assert(false);
        }

        assert(coro.event == EVENT_STOP);
        CORO_HANDLE_ALL(coro, EVENT_STOP);

        // Only stop logging after connmgr_stop()
        wifi_promiscuous_enable(0);
        user_dprintf("stopped");
        coro_interrupt_later = 0;
    }

    assert(false);

    CORO_END();
}

// Async client APIs

ICACHE_FLASH_ATTR
void connmgr_init() {
    CORO_START(coro, connmgr_init_impl);
}

ICACHE_FLASH_ATTR
void connmgr_start() {
    CORO_RESUME(coro, EVENT_START);
}

ICACHE_FLASH_ATTR
void connmgr_stop() {
    CORO_INTERRUPT(coro, EVENT_STOP);
}

ICACHE_FLASH_ATTR
void connmgr_write(struct pbuf *p) {
    assert(p != NULL);
    if (write_head == NULL) {
        write_head = p;
    } else {
        pbuf_cat(write_head, p);
    }
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
            if (false) { // check types
                ap_gw_addr = event->event_info.got_ip.gw;
            }
            os_memcpy(&ap_gw_addr, &event->event_info.got_ip.gw, sizeof(ap_gw_addr));
            assert_heap();

            CORO_RESUME(coro, EVENT_GOT_IP);
            user_dprintf("got ip done");
            break;
        case EVENT_STAMODE_DISCONNECTED:
            user_dprintf("disconnected");
            CORO_INTERRUPT(coro, EVENT_DISASSOCIATE);
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
    user_dprintf("reconnect due to %d\x1b[35m", err);
    ssl_pcb = NULL;
    if (ssl != NULL) {
        ssl->hs_status = SSL_ERROR_DEAD;
    }
    // This should be race-free, since we're in lwIP
    // We can be called through tcp_abort() in connmgr_init_impl
    CORO_INTERRUPT(coro, EVENT_ABORT);
    user_dprintf("done");
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
    user_dprintf("tcp connected: err=%d", err);
    assert(err == ERR_OK);
    assert(tpcb != NULL);
    assert(ssl_pcb != NULL);
    assert(tpcb == ssl_pcb);
    CORO_RESUME(coro, EVENT_CONNECT);
    return ssl_pcb != tpcb ? ERR_ABRT : ERR_OK;
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    assert(tpcb != NULL);
    assert(ssl_pcb != NULL);
    assert(tpcb == ssl_pcb);
    user_dprintf("%p", p);
    if (p == NULL) {
        user_dprintf("err=%d", err);
        return ERR_OK;
    }
    if (err != ERR_OK) {
        user_dprintf("err=%d", err);
        assert(false);
    }

    USER_INTR_LOCK();
    assert(p->ref >= 1);
    if (ssl_pcb_recv_buf == NULL) {
        ssl_pcb_recv_buf = p;
    } else {
        pbuf_cat(ssl_pcb_recv_buf, p);
        // We'll send EVENT_IDLE in icmp_net_process_queued_pbufs_callback.
        // That way we'll be out of lwIP.
    }
    USER_INTR_UNLOCK();
    return ssl_pcb != tpcb ? ERR_ABRT : err;
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_poll_cb(void *arg, struct tcp_pcb *tpcb) {
    assert(tpcb != NULL);
    assert(ssl_pcb != NULL);
    assert(tpcb == ssl_pcb);
    user_dprintf("");
    CORO_RESUME(coro, EVENT_POLL);
    return ssl_pcb != tpcb ? ERR_ABRT : ERR_OK;
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_sent_cb(void * arg, struct tcp_pcb * tpcb, u16_t len) {
    user_dprintf("");
    return ssl_pcb_poll_cb(arg, tpcb);
}

ICACHE_FLASH_ATTR
void icmp_net_process_queued_pbufs_callback() {
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
    if (CORO_INTERRUPTED(coro)) { \
        os_port_impure_errno = EIO; \
        return -1; \
    }

__attribute__((used))
ICACHE_FLASH_ATTR
ssize_t os_port_socket_read(int fd, void *buf, size_t len) {
    struct tcp_pcb *tpcb = (struct tcp_pcb *)fd;
    assert(len > 0);
    //user_dprintf("%p %d", buf, len);
    CONNMGR_TESTCANCEL();
    const ssize_t ret = len;
    // Read from the linked list.
    while (len > 0) {
        // Check for a packet.
        USER_INTR_LOCK();
        if (ssl_pcb_recv_buf == NULL) {
            USER_INTR_UNLOCK();
            if (ret == (ssize_t)len) {
                os_port_impure_errno = EAGAIN;
                return -1;
            } else {
                return ret - len;
            }
        }
        assert(ssl_pcb_recv_buf->ref == 1);

        // Try to read read_len from the buffer.
        u16_t read_len = ssl_pcb_recv_buf->len;
        if (read_len > len) {
            // Read < 1 pbuf. Read was satisfied. Only update source pointers.
            memcpy(buf, ssl_pcb_recv_buf->payload, len);
            pbuf_header(ssl_pcb_recv_buf, -len); // always succeeds
            tcp_recved(tpcb, len);
            USER_INTR_UNLOCK();
            break;
        }

        // Pop off the first pbuf.
        struct pbuf *prev_pbuf = ssl_pcb_recv_buf;
        pbuf_ref(ssl_pcb_recv_buf = prev_pbuf->next);
        pbuf_dechain(prev_pbuf);
        assert(ssl_pcb_recv_buf == NULL || ssl_pcb_recv_buf->ref == 1);
        USER_INTR_UNLOCK();

        // Read >= 1 pbuf. Only update destination pointers.
        memcpy(buf, prev_pbuf->payload, read_len);
        *(char **)&buf += read_len;
        len -= read_len;
        tcp_recved(tpcb, read_len);

        // Free the pbuf.
        pbuf_free(prev_pbuf);
    }

    return ret;
}

__attribute__((used))
ICACHE_FLASH_ATTR
ssize_t os_port_socket_write(int fd, const void *buf, size_t len) {
    struct tcp_pcb *tpcb = (struct tcp_pcb *)fd;
    user_dprintf("%p %d", buf, len);
    CONNMGR_TESTCANCEL();
    // TODO figure out how to avoid reallocation
    err_t rc = tcp_write(tpcb, buf, len, TCP_WRITE_FLAG_COPY);
    switch (rc) {
        case ERR_OK:
            user_dprintf("done");
            return len;
        case ERR_MEM:
            user_dprintf("no memory");
            os_port_impure_errno = EBUSY; // EAGAIN is taken
            return -1;
        default:;
            user_dprintf("write failed");
            os_port_impure_errno = EIO;
            return -1;
    }
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
