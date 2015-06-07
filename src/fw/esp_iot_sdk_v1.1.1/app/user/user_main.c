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
    user_dprintf("wifi_handle_event_cb(event={event=%d})\n", event->event);
    switch (event->event) {
        case EVENT_STAMODE_GOT_IP:
            user_dprintf("wifi_handle_event_cb: ip=" IPSTR " mask=" IPSTR " gw=" IPSTR "\n",
                      IP2STR(&event->event_info.got_ip.ip),
                      IP2STR(&event->event_info.got_ip.mask),
                      IP2STR(&event->event_info.got_ip.gw));

            icmp_config.bind_ip = event->event_info.got_ip.ip;
            dhcp_start(&icmp_tun);
            break;
        default:
            user_dprintf("wifi_handle_event_cb: disconnected\n");

            dhcp_stop(&icmp_tun);
            break;
    }
}

void user_rf_pre_init(void) {
}

void user_init(void) {
    uart_div_modify(0, UART_CLK_FREQ / 115200);
    os_delay_us(1000000);
    os_printf("user_init()\n");

    wifi_set_opmode_current(STATION_MODE);
    {
        struct station_config *config = (struct station_config *)os_zalloc(sizeof(struct station_config));
        const static char *ssid = "icmp-test";
        os_memcpy(config->ssid, ssid, os_strlen(ssid));
        wifi_station_set_config_current(config);
    }
    wifi_station_set_auto_connect(1);
    wifi_station_set_reconnect_policy(true);

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
        os_printf("user_init: netif_add failed\n");
    }

    wifi_set_event_handler_cb(wifi_handle_event_cb);
}
