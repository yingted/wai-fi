#ifndef __ICMP_NET_H__
#define __ICMP_NET_H__

#include "user_config.h"
#include "ip_addr.h"
#include "lwip/err.h"
#include "lwip/netif.h"

struct icmp_net_config {
    struct ip_addr relay_ip;
    struct netif *slave;
// private:
    struct icmp_net_config *next;
    netif_status_callback_fn dhcp_bound_callback;
};

err_t icmp_net_init(struct netif *netif);
void icmp_net_set_dhcp_bound_callback(struct netif *netif, netif_status_callback_fn cb);

#endif

