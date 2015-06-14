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

ICACHE_FLASH_ATTR
static void espconn_connect_cb(void *arg) {
    user_dprintf("arg=%p", arg);
}

ICACHE_FLASH_ATTR
static void espconn_reconnect_cb(void *arg, sint8 err) {
    user_dprintf("reconnect due to %u", err);
    espconn_connect_cb(arg);
}

ICACHE_FLASH_ATTR
static inline void on_tunnel_established() {
    user_dprintf("tunnel established");

    os_memset(&con, 0, sizeof(con));
    con.type = ESPCONN_TCP;
    con.state = ESPCONN_NONE;
    {
        static esp_tcp tcp;
        memset(&tcp, 0, sizeof(tcp));
        tcp.remote_port = 55555;
        tcp.local_port = espconn_port();
        const static unsigned char local_ip[] = {192, 168, 10, 96};
        const static unsigned char remote_ip[] = {192, 168, 10, 1};
        os_memcpy(tcp.local_ip, local_ip, sizeof(local_ip));
        os_memcpy(tcp.remote_ip, remote_ip, sizeof(remote_ip));

        con.proto.tcp = &tcp;
    }
    espconn_regist_connectcb(&con, espconn_connect_cb);
    espconn_regist_reconcb(&con, espconn_reconnect_cb);

    user_dprintf("starting connection");
    sint8 rc = espconn_secure_connect(&con);
    user_dprintf("started connection: %u", rc);
    user_dprintf("heap: %u", system_get_free_heap_size());
    if (rc) {
        user_dprintf("espconn_secure_connect: error %u", rc);
        return;
    }
    secure_connected = true;
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

            if (secure_connected) {
                espconn_secure_disconnect(&con);
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

void on_timer(void *arg) {
    register void *epc;
    asm(
        "rsr %0, 177"
        :"=r"(epc)
    );
    user_dprintf("epc: %p", epc);
}

ICACHE_FLASH_ATTR
void user_init(void) {
    uart_div_modify(0, UART_CLK_FREQ / 115200);
    user_dprintf("user_init()");
    //ets_wdt_disable();
    {
        static os_timer_t timer;
        os_timer_disarm(&timer);
        os_timer_setfn(&timer, (os_timer_func_t *)on_timer, NULL);
        os_timer_arm(&timer, 1000, 1);
    }

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
}

SSL_CTX *__real_ssl_ctx_new(uint32_t options, int num_sessions);
ICACHE_FLASH_ATTR
SSL_CTX *__wrap_ssl_ctx_new(uint32_t options, int num_sessions) {
    user_dprintf("%u %d", options, num_sessions);
    return __real_ssl_ctx_new(options, num_sessions);
}

SSL *__real_SSLClient_new(SSL_CTX *ssl_ctx, struct tcp_pcb *SslClient_pcb, const uint8_t *session_id, uint8_t sess_id_size);
ICACHE_FLASH_ATTR
SSL *__wrap_SSLClient_new(SSL_CTX *ssl_ctx, struct tcp_pcb *SslClient_pcb, const uint8_t *session_id, uint8_t sess_id_size) {
    user_dprintf("%p %p %p %u", ssl_ctx, SslClient_pcb, session_id, sess_id_size);
    return __real_SSLClient_new(ssl_ctx, SslClient_pcb, session_id, sess_id_size);
}

sint8 __real_espconn_ssl_client(struct espconn *espconn);
ICACHE_FLASH_ATTR
sint8 __wrap_espconn_ssl_client(struct espconn *espconn) {
    typedef struct _comon_pkt{
        void *pcb;
        int remote_port;
        uint8 remote_ip[4];
        uint8 *ptrbuf;
        uint16 cntr;
        uint16 write_len;
        uint16 write_total;
        sint8  err;
        uint32 timeout;
        uint32 recv_check;
        enum espconn_option espconn_opt;
        os_timer_t ptimer;
    }comon_pkt;
    typedef struct _espconn_msg{
        struct espconn *pespconn;
        comon_pkt pcommon;
        uint8 count_opt;
        void *preverse;
        void *pssl;
        struct _espconn_msg *pnext;
    }espconn_msg;
    extern espconn_msg *plink_active;
    user_dprintf("%p (plink_active %p)", espconn, plink_active);
    sint8 ret = __real_espconn_ssl_client(espconn);
    user_dprintf("%u (plink_active %p)", ret, plink_active);
    return ret;
}

long __real_ets_post(long a, long b, long c);
long __wrap_ets_post(long a, long b, long c) {
    static int lock = 0;
    ++lock;
    if (lock == 1) {
        register void *a0 asm("a0");
        user_dprintf("%p: %ld %ld %ld", a0, a, b, c);
    }
    long ret = __real_ets_post(a, b, c);
    if (lock == 1) {
        user_dprintf("%ld", ret);
        ets_intr_unlock();
    }
    --lock;
    return ret;
}
