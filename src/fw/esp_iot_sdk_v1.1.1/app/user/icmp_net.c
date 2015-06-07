#include "osapi.h"
#include "private_api.h"
#include "icmp_net.h"
#include "lwip/icmp.h"

static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    os_printf("icmp_net_linkoutput()\n");
    return ERR_OK;
}

static err_t icmp_net_output(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr) {
	return icmp_net_linkoutput(netif, p);
}

err_t icmp_net_init(struct netif *netif) {
	netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_POINTTOPOINT;
	netif->output = icmp_net_output;
	netif->linkoutput = netif->linkoutput;
	return dhcp_start(netif);
}

void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
	os_printf("icmp_input()\n");
	__real_icmp_input(p, inp);
}
