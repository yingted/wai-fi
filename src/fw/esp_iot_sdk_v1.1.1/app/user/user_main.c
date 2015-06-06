#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"

#include "user_interface.h"

void user_wifi(System_Event_t *event)
{
    os_printf("event %x\n", event);
    switch (event->event) {
        case EVENT_STAMODE_GOT_IP:
            os_printf("ip:" IPSTR ",mask:" IPSTR ",gw:" IPSTR "\n",
                      IP2STR(&event->event_info.got_ip.ip),
                      IP2STR(&event->event_info.got_ip.mask),
                      IP2STR(&event->event_info.got_ip.gw));
            break;
    }
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

    wifi_set_event_handler_cb(user_wifi);
}
