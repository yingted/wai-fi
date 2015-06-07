#ifndef __ICMP_NET_H__
#define __ICMP_NET_H__

#include "user_config.h"
#include "ip_addr.h"
#include "lwip/err.h"
#include "lwip/netif.h"

struct icmp_net_config {
    struct ip_addr bind_ip;
    struct icmp_net_config *next;
    struct netif *netif;
};

err_t icmp_net_init(struct netif *netif);

#endif

