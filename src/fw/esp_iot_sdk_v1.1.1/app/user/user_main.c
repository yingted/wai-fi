#include "user_config.h"
#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"
#include "user_interface.h"
#include "icmp_net.h"
#include "lwip/ip4.h"

#include "lwip/dhcp.h"
#define DHCP_MAX_MSG_LEN_MIN_REQUIRED  576
err_t
my_dhcp_start(struct netif *netif)
{
  struct dhcp *dhcp;
  err_t result = ERR_OK;

  LWIP_ERROR("netif != NULL", (netif != NULL), return ERR_ARG;);
  dhcp = netif->dhcp;
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_start(netif=%p) %c%c%"U16_F"\n", (void*)netif, netif->name[0], netif->name[1], (u16_t)netif->num));
  /* Remove the flag that says this netif is handled by DHCP,
     it is set when we succeeded starting. */
  netif->flags &= ~NETIF_FLAG_DHCP;

  /* check hwtype of the netif */
  if ((netif->flags & NETIF_FLAG_ETHARP) == 0) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start(): No ETHARP netif\n"));
    return ERR_ARG;
  }

  /* check MTU of the netif */
  if (netif->mtu < DHCP_MAX_MSG_LEN_MIN_REQUIRED) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start(): Cannot use this netif with DHCP: MTU is too small\n"));
    return ERR_MEM;
  }

  /* no DHCP client attached yet? */
  if (dhcp == NULL) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start(): starting new DHCP client\n"));
    dhcp = (struct dhcp *)mem_malloc(sizeof(struct dhcp));
    if (dhcp == NULL) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start(): could not allocate dhcp\n"));
      return ERR_MEM;
    }
    /* store this dhcp client in the netif */
    netif->dhcp = dhcp;
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start(): allocated dhcp"));
  /* already has DHCP client attached */
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_start(): restarting DHCP configuration\n"));
    if (dhcp->pcb != NULL) {
      udp_remove(dhcp->pcb);
    }
    LWIP_ASSERT("pbuf p_out wasn't freed", dhcp->p_out == NULL);
    LWIP_ASSERT("reply wasn't freed", dhcp->msg_in == NULL );
  }
    
  /* clear data structure */
  memset(dhcp, 0, sizeof(struct dhcp));
  /* dhcp_set_state(&dhcp, DHCP_OFF); */
  /* allocate UDP PCB */
}

static struct netif icmp_tun;
static struct icmp_net_config icmp_config;
static struct ip_info linklocal_info = {
    .ip = { IPADDR_ANY },
    .netmask = { IPADDR_ANY },
    .gw = { IPADDR_ANY },
};

void wifi_handle_event_cb(System_Event_t *event) {
    user_dprintf("event={event=%d}", event->event);
    switch (event->event) {
        case EVENT_STAMODE_GOT_IP:
            user_dprintf("ip=" IPSTR " mask=" IPSTR " gw=" IPSTR,
                      IP2STR(&event->event_info.got_ip.ip),
                      IP2STR(&event->event_info.got_ip.mask),
                      IP2STR(&event->event_info.got_ip.gw));

            icmp_config.bind_ip = event->event_info.got_ip.ip;
            netif_set_up(&icmp_tun);
            err_t rc = my_dhcp_start(&icmp_tun);
            if (rc != ERR_OK) {
                user_dprintf("dhcp error: %d == %d", rc, ERR_CLSD);
            }
            user_dprintf("dhcp: %p", icmp_tun.dhcp);
            break;
        default:
            user_dprintf("disconnected");

            dhcp_stop(&icmp_tun);
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
