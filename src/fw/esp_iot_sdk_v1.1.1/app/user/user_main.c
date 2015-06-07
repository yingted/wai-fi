#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"
#include "user_interface.h"
#include "icmp_net.h"

void wifi_handle_event_cb(System_Event_t *event)
{
    os_printf("wifi_handle_event_cb(event={event=%d})\n", event, event->event);
    switch (event->event) {
        case EVENT_STAMODE_GOT_IP:
            os_printf("wifi_handle_event_cb: ip=" IPSTR " mask=" IPSTR " gw=" IPSTR "\n",
                      IP2STR(&event->event_info.got_ip.ip),
                      IP2STR(&event->event_info.got_ip.mask),
                      IP2STR(&event->event_info.got_ip.gw));
            break;
        default:
            os_printf("wifi_handle_event_cb: disconnected\n");
    }
}

void user_icmp_net_rx() {
    os_printf("user_icmp_net_rx()\n");
}

void user_rf_pre_init(void)
{
}

void user_init(void)
{
    uart_div_modify(0, UART_CLK_FREQ / 115200);

    wifi_set_opmode_current(STATION_MODE);
    {
        struct station_config *config = (struct station_config *)os_zalloc(sizeof(struct station_config));
        const static char *ssid = "icmp-test";
        os_memcpy(config->ssid, ssid, os_strlen(ssid));
        wifi_station_set_config_current(config);
    }
    wifi_station_set_auto_connect(1);
    wifi_station_set_reconnect_policy(true);

    wifi_set_event_handler_cb(wifi_handle_event_cb);
}
