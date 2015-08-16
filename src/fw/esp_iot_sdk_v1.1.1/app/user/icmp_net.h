#ifndef __ICMP_NET_H__
#define __ICMP_NET_H__

#include <user_config.h>
#include <ip_addr.h>
#include <lwip/err.h>
#include <lwip/netif.h>

// Must be a power of 2
#define ICMP_NET_QSIZE 256U
#define ICMP_NET_MAX_KEEPALIVE 8U
#define ICMP_NET_MIN_KEEPALIVE 2U
// TTL (3 means it survives 3 timeouts and dies on the 4th), in 5 s units
#define ICMP_NET_TTL (155 / 5)

struct icmp_net_config {
    struct ip_addr relay_ip;
    struct netif *slave, *netif;
// private:
    struct icmp_net_config *next;
    // recv_i <= send_i
    uint16_t recv_i, send_i;
    uint16_t icmp_id;
    /**
     * The packet queue is stored in:
     * queue[i % ICMP_NET_QSIZE] for i = (recv_i + 1) ... (send_i - 1)
     * The invariant is: send_i - recv_i
     * Other values are undefined.
     * The pipe is given by:
     * send_i - recv_i
     * The queue size is given by:
     * send_i - (recv_i + 1)
     * Where the recv_i is the lowest-index packet still not received.
     */
    struct pbuf *queue[ICMP_NET_QSIZE];
    uint8_t ttl[ICMP_NET_QSIZE];
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

