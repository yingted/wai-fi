#ifndef __ICMP_NET_H__
#define __ICMP_NET_H__

#include "user_config.h"
#include "ip_addr.h"
#include "lwip/err.h"
#include "lwip/netif.h"

// Must be a power of 2
#define ICMP_NET_QSIZE 4U
#define ICMP_NET_MAX_KEEPALIVE 1U
#define ICMP_NET_MIN_KEEPALIVE 1U

struct icmp_net_config {
    struct ip_addr relay_ip;
    struct netif *slave, *netif;
// private:
    struct icmp_net_config *next;
    // recv_i <= send_i
    uint16_t recv_i, send_i;
    /**
     * The packet queue is stored in:
     * queue[i % ICMP_NET_QSIZE] for i = (next_recv_seqno + 1) ... (next_send_seqno - 1)
     * The invariant is: next_send_seqno - next_recv_seqno
     * Other values are undefined.
     * The pipe is given by:
     * next_send_seqno - next_recv_seqno
     * The queue size is given by:
     * next_send_seqno - (next_recv_seqno + 1)
     * Where the next_recv_seqno is the lowest-index packet still not received.
     */
    struct pbuf *queue[ICMP_NET_QSIZE];
};

#define ICMP_NET_CONFIG_QLEN(config) ((config)->send_i - (config)->recv_i)
#define ICMP_NET_CONFIG_CAN_KEEPALIVE(config) (ICMP_NET_CONFIG_QLEN(config) < ICMP_NET_MAX_KEEPALIVE)
#define ICMP_NET_CONFIG_MUST_KEEPALIVE(config) (ICMP_NET_CONFIG_QLEN(config) < ICMP_NET_MIN_KEEPALIVE)
#define ICMP_NET_CONFIG_LOCK(config) USER_INTR_LOCK()
#define ICMP_NET_CONFIG_UNLOCK(config) USER_INTR_UNLOCK()

err_t icmp_net_init(struct netif *netif);
void icmp_net_set_dhcp_bound_callback(struct netif *netif, netif_status_callback_fn cb);
void icmp_net_enslave(struct icmp_net_config *config, struct netif *slave);
void icmp_net_unenslave(struct icmp_net_config *config);
extern short icmp_net_device_id;

#endif

