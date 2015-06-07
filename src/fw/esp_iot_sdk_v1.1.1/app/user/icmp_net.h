#ifndef __ICMP_NET_H__
#define __ICMP_NET_H__

#include "user_config.h"
#include "ip_addr.h"
#include "lwip/err.h"

//#include "lwip/netif.h"
struct netif;

struct icmp_net_config {
    struct ip_addr bind_ip;
};

err_t icmp_net_init(struct netif *netif);

#endif

