#include "user_config.h"
#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"
#include "user_interface.h"
#include "icmp_net.h"
#include "lwip/ip4.h"

static struct netif icmp_tun;
static struct icmp_net_config icmp_config;
static struct ip_info linklocal_info = {
    .ip = { IPADDR_ANY },
    .netmask = { IPADDR_ANY },
    .gw = { IPADDR_ANY },
};

void wifi_handle_event_cb(System_Event_t *event) {
    user_dprintf("event={event=%d}", event->event);
    struct netif *saved_default = NULL;
    switch (event->event) {
        case EVENT_STAMODE_GOT_IP:
            user_dprintf("ip=" IPSTR " mask=" IPSTR " gw=" IPSTR,
                      IP2STR(&event->event_info.got_ip.ip),
                      IP2STR(&event->event_info.got_ip.mask),
                      IP2STR(&event->event_info.got_ip.gw));

            user_dprintf("route to " IPSTR ": %p", IP2STR(&event->event_info.got_ip.gw), ip_route(&event->event_info.got_ip.gw));
            icmp_config.slave = ip_route(&event->event_info.got_ip.gw);
            user_dprintf("route via " IPSTR, IP2STR(&icmp_config.slave->ip_addr));

{
    user_dprintf("=========================================================");
    struct netif *netif = &icmp_tun;
    struct pbuf *p = pbuf_alloc(PBUF_IP, 0, PBUF_RAM);
    //if (ip_output_if(p, &netif->ip_addr, &netif->gw, ICMP_TTL, 0, IP_PROTO_ICMP, netif)) {
    if (ip_output(p, &netif->ip_addr, &netif->gw, ICMP_TTL, 0, IP_PROTO_ICMP)) {
        user_dprintf("error!");
    }
}

            assert(saved_default == NULL);
            assert(netif_default != &icmp_tun);
            saved_default = netif_default;
            netif_default = &icmp_tun;

            err_t rc = dhcp_start(&icmp_tun);
            user_dprintf("dhcp_start returned %d", (int)rc);
            if (rc != ERR_OK) {
                user_dprintf("dhcp error: %d", rc);
            }
            user_dprintf("dhcp: %p", icmp_tun.dhcp);
            break;
        default:
            user_dprintf("disconnected");

            dhcp_stop(&icmp_tun);

            if (netif_default == &icmp_tun) {
                netif_default = saved_default;
                saved_default = NULL;
            }
            break;
    }
}

void icmp_tun_dhcp_bound_cb(struct netif *netif) {
    user_dprintf("ip_addr: " IPSTR "", IP2STR(&netif->ip_addr));
}

void user_rf_pre_init(void) {
}

void user_init(void) {
    uart_div_modify(0, UART_CLK_FREQ / 115200);
#ifndef NDEBUG
    os_delay_us(1000000);
    user_dprintf("user_init()");
#endif

    wifi_set_opmode_current(STATION_MODE);
    {
        struct station_config *config = (struct station_config *)os_zalloc(sizeof(struct station_config));
        const static char *ssid = "icmp-test";
        os_memcpy(config->ssid, ssid, os_strlen(ssid));
        wifi_station_set_config_current(config);
    }
    wifi_station_set_auto_connect(1);
    wifi_station_set_reconnect_policy(true);

    icmp_config.relay_ip.addr = ipaddr_addr("192.168.8.1");

    // Create the ICMP tunnel device and never delete it.
    if (!netif_add(
            &icmp_tun,
            &linklocal_info.ip,
            &linklocal_info.netmask,
            &linklocal_info.gw,
            &icmp_config,
            icmp_net_init,
            ip_input
        )) {
        user_dprintf("netif_add failed");
    }

    icmp_net_set_dhcp_bound_callback(&icmp_tun, icmp_tun_dhcp_bound_cb);

    wifi_set_event_handler_cb(wifi_handle_event_cb);
}
