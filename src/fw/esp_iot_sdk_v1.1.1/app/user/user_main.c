#include "user_config.h"
#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"
#include "user_interface.h"
#include "icmp_net.h"
#include "lwip/ip4.h"
#include "espressif/esp8266/uart_register.h"

static struct netif icmp_tap;
static struct icmp_net_config icmp_config;
static struct ip_info linklocal_info = {
    .ip = { IPADDR_ANY },
    .netmask = { IPADDR_ANY },
    .gw = { IPADDR_ANY },
};

void wifi_handle_event_cb(System_Event_t *event) {
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

            assert(saved_default == NULL);
            assert(netif_default != &icmp_tap);
            saved_default = netif_default;
            netif_default = &icmp_tap;

            err_t rc = dhcp_start(&icmp_tap);
            user_dprintf("dhcp_start returned %d", (int)rc);
            if (rc != ERR_OK) {
                user_dprintf("dhcp error: %d", rc);
            }
            user_dprintf("dhcp: %p", icmp_tap.dhcp);
            break;
        default:
            user_dprintf("disconnected");

            dhcp_stop(&icmp_tap);

            if (netif_default == &icmp_tap) {
                netif_default = saved_default;
                saved_default = NULL;
            }
            break;
    }
}

void icmp_tap_dhcp_bound_cb(struct netif *netif) {
    user_dprintf("ip_addr: " IPSTR, IP2STR(&netif->ip_addr));
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

    icmp_config.relay_ip.addr = ipaddr_addr("192.168.9.1");

    // Create the ICMP tap device and never delete it.
    if (!netif_add(
            &icmp_tap,
            &linklocal_info.ip,
            &linklocal_info.netmask,
            &linklocal_info.gw,
            &icmp_config,
            icmp_net_init,
            ip_input
        )) {
        user_dprintf("netif_add failed");
    }

    icmp_net_set_dhcp_bound_callback(&icmp_tap, icmp_tap_dhcp_bound_cb);

    wifi_set_event_handler_cb(wifi_handle_event_cb);
}
