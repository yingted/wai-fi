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
#define __XTENSA_WINDOWED_ABI__ 0
#include <setjmp.h>
#define setjmp __builtin_setjmp
#define longjmp __builtin_longjmp

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
static bool ssl_should_connect = false;

static bool filter_dest = false, filter_bssid = false;

static void ssl_connect();
static void ssl_disconnect();
static void os_port_blocking_resume();
static void os_port_blocking_call(void (*fn)(void *), void *arg);
static bool os_port_is_blocked = false, os_port_is_interrupted = false;
#ifndef NDEBUG
static bool os_port_is_worker = false;
#endif
extern int os_port_impure_errno;

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
            if (ssl_pcb != NULL) { // ssl_connect starts off by setting ssl_pcb
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
    ssl_ctx = ssl_ctx_new(0, 0);
    err_t rc = add_cert_auth(ssl_ctx, default_ca_certificate, default_ca_certificate_len);
    assert(rc == SSL_OK);
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
}

ICACHE_FLASH_ATTR
void connmgr_start() {
    wifi_set_opmode_current(NULL_MODE);
    wifi_set_event_handler_cb(wifi_handle_event_cb);
    wifi_set_opmode_current(STATION_MODE);
    {
        static struct station_config config; // 0-initialized
        const static char *ssid = "uw-wifi-setup-no-encryption";
        os_memcpy(config.ssid, ssid, os_strlen(ssid));
        wifi_station_set_config_current(&config);
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
    assert(connmgr_connected || os_port_is_blocked);
    if (connmgr_connected) {
        assert(ssl != NULL);
        ssl_free(ssl);
        if (ssl_pcb != NULL) {
            tcp_abort(ssl_pcb);
        }
        connmgr_set_connected(false);
        connmgr_disconnect_cb();
    }
    if (os_port_is_blocked) {
        assert(!os_port_is_worker);
        os_port_is_interrupted = true;
        os_port_blocking_resume();
    }
    assert(ssl == NULL);
    if (ssl_pcb) {
        tcp_abort(ssl_pcb);
        ssl_pcb = NULL;
        ssl_should_connect = false;
    }

    assert(!connmgr_connected);
    assert(!os_port_is_blocked);
    assert(!os_port_is_worker);
    assert(!os_port_is_interrupted);
}

ICACHE_FLASH_ATTR
static void ssl_pcb_err_cb(void *arg, err_t err) {
    debug_esp_assert_not_nmi(); // should fail
    user_dprintf("reconnect due to %d\x1b[35m", err);
    ssl_pcb = NULL;
    ssl_should_connect = false;
    ssl_disconnect();
    schedule_reconnect();
}

ICACHE_FLASH_ATTR
static void ssl_connect_impl(void *arg) {
    // XXX use session id
    ssl = ssl_client_new(ssl_ctx, (int)ssl_pcb, NULL, 0);
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
    assert(err == ERR_OK);
    user_dprintf("tcp connected: err=%d", err);
    ssl_should_connect = true;
    return ERR_OK;
}

struct connmgr_send_impl_arg {
    const uint8_t *buf;
    int len;
};
ICACHE_FLASH_ATTR
static void connmgr_send_impl(void *void_arg) {
    struct connmgr_send_impl_arg *arg = void_arg;
    user_dprintf("%p", arg);
    // This call always writes everything, as per the API
    ssl_write(ssl, arg->buf, arg->len);
}

ICACHE_FLASH_ATTR
void connmgr_send(const uint8_t *buf, int len) {
    struct connmgr_send_impl_arg arg = {
        .buf = buf,
        .len = len,
    };
    os_port_blocking_call(connmgr_send_impl, &arg);
}

static bool is_read_blocked = false;
static struct {
    uint8_t *buf;
    size_t len;
} ssl_pcb_recv_cb_arg;
static struct pbuf *ssl_pcb_recv_buf = NULL;
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
    }
    return err;
}

ICACHE_FLASH_ATTR
void icmp_net_process_queued_pbufs_callback() {
    user_dprintf("");
    if (ssl_pcb == NULL) {
        // Pretend not to get network events.
        return;
    }

    if (!connmgr_connected) {
        if (os_port_is_blocked) {
            // We're connecting
            return;
        }
        if (ssl_should_connect) {
            ssl_should_connect = false;
            // We aren't connecting, but should.
            os_port_blocking_call(ssl_connect_impl, NULL);
            assert(os_port_is_blocked);
            assert(!os_port_is_worker);
        }
        return;
    }

    if (ssl_pcb_recv_buf == NULL) {
        // No queued pbufs
        return;
    }

    for (;;) {
        user_dprintf("resuming coroutine");
        // Exhaust the coroutine
        while (is_read_blocked) {
            // Check that we can send it something
#define READ_BUF ssl_pcb_recv_cb_arg.buf
#define READ_LEN ssl_pcb_recv_cb_arg.len
            for (;;) {
                // Try to read read_len from the buffer.
                u16_t read_len = ssl_pcb_recv_buf->len;
                if (read_len > READ_LEN) {
                    // Read < 1 pbuf. Read was satisfied. Don't bother updating buffer pointers.
                    memcpy(READ_BUF, ssl_pcb_recv_buf->payload, READ_LEN);
                    break;
                }
                // Read >= 1 pbuf. Update pointers.
                memcpy(READ_BUF, ssl_pcb_recv_buf->payload, read_len);
                *(char **)&READ_BUF += read_len;
                READ_LEN -= read_len;

                // Free the pbuf.
                struct pbuf *prev_pbuf = ssl_pcb_recv_buf;
                ssl_pcb_recv_buf = prev_pbuf->next;
                if (ssl_pcb_recv_buf == NULL) {
                    return;
                }
                pbuf_ref(ssl_pcb_recv_buf);
                pbuf_dechain(prev_pbuf);
                pbuf_free(prev_pbuf);
            }
#undef READ_BUF
#undef READ_LEN
            os_port_blocking_resume();
        }

        assert(!is_read_blocked);
        assert(!os_port_is_worker);
        assert(!os_port_is_blocked);
        assert(!os_port_is_interrupted);

        // Callback time. Read some data and such.
        // We can't call any axTLS APIs until we unwind out of lwIP, since axTLS
        // may block on some lwIP function.
        if (!connmgr_connected) {
            USER_INTR_LOCK();
            connmgr_set_connected(true);
            USER_INTR_UNLOCK();

            user_dprintf("connected\x1b[34m");
            filter_dest = filter_bssid = true;
            promisc_start();
            connmgr_connect_cb();
            continue;
        }

        break;
    }
}

static bool is_write_blocked = false;
ICACHE_FLASH_ATTR
static err_t ssl_pcb_poll_cb(void *arg, struct tcp_pcb *tpcb) {
    user_dprintf("");
    if (is_write_blocked) {
        os_port_blocking_resume();
    }
    return ERR_OK;
}

ICACHE_FLASH_ATTR
static err_t ssl_pcb_sent_cb(void * arg, struct tcp_pcb * tpcb, u16_t len) {
    user_dprintf("");
    return ssl_pcb_poll_cb(arg, tpcb);
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

    assert(!connmgr_connected);
    assert_heap();
    USER_INTR_UNLOCK();
}

// Coroutine implementation

// Only supports one blocking call at once.
static jmp_buf os_port_main_env, os_port_worker_env;
__attribute__((returns_twice))
ICACHE_FLASH_ATTR
static void os_port_blocking_call(void (*fn)(void *), void *arg) {
    static char stack[1024];
    assert(!os_port_is_blocked);
    assert(!os_port_is_worker);
    user_dprintf("%p %p", fn, arg);
    if (!setjmp(os_port_main_env)) {
        os_port_is_blocked = false;
#ifndef NDEBUG
        os_port_is_worker = true;
#endif
        static void *volatile sp;
        register void *stack_top = stack + sizeof(stack);
        __asm__ __volatile__("\
            mov %[sp], a1\n\
            mov a1, %[stack_top]\n\
        ":[sp] "=r"(sp):[stack_top] "r"(stack_top));
        (*fn)(arg);
        __asm__ __volatile__("\
            mov a1, %[sp]\n\
        "::[sp] "r"(sp));

        assert(!os_port_is_blocked);
#ifndef NDEBUG
        os_port_is_worker = false;
#endif
        os_port_is_interrupted = false;
    }
}

ICACHE_FLASH_ATTR
static void os_port_blocking_yield() {
    assert(!os_port_is_blocked);
    assert(os_port_is_worker);
    user_dprintf("");
    if (!setjmp(os_port_worker_env)) {
        os_port_is_blocked = true;
#ifndef NDEBUG
        os_port_is_worker = false;
#endif
        longjmp(os_port_main_env, 1);
    }
}

ICACHE_FLASH_ATTR
static void os_port_blocking_resume() {
    assert(os_port_is_blocked);
    assert(!os_port_is_worker);
    if (!setjmp(os_port_main_env)) {
        os_port_is_blocked = false;
#ifndef NDEBUG
        os_port_is_worker = true;
#endif
        longjmp(os_port_worker_env, 1);
    }
}

// Blocking socket implementation

#define CANCELLATION_POINT() \
    if (os_port_is_interrupted) { \
        os_port_impure_errno = EIO; \
        return -1; \
    }

__attribute__((used))
ICACHE_FLASH_ATTR
ssize_t os_port_socket_read(int fd, void *buf, size_t len) {
    assert(len > 0);
    CANCELLATION_POINT();
    ssl_pcb_recv_cb_arg.buf = (uint8_t *)buf;
    ssl_pcb_recv_cb_arg.len = len;
    os_port_blocking_yield();
    CANCELLATION_POINT();
    return len;
}

__attribute__((used))
ICACHE_FLASH_ATTR
ssize_t os_port_socket_write(int fd, const void *volatile buf, volatile size_t len) {
    struct tcp_pcb *volatile tpcb = (struct tcp_pcb *)fd;
    CANCELLATION_POINT();
    for (;;) {
        err_t rc = tcp_write(tpcb, buf, len, 0);
        switch (rc) {
            case ERR_OK:
                return len;
            case ERR_MEM:
                is_write_blocked = true;
                os_port_blocking_yield();
                is_write_blocked = false;
                CANCELLATION_POINT();
                continue;
            default:;
                os_port_impure_errno = rc;
                return -1;
        }
    }
    return len;
}

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
