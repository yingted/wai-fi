#include "osapi.h"
#include "private_api.h"
#include "icmp_net.h"
#include "lwip/icmp.h"
#include "lwip/ip.h"

static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    os_printf("icmp_net_linkoutput()\n");
    return ERR_OK;
}

static err_t icmp_net_output(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr) {
    if (!ip_addr_cmp(ipaddr, &netif->gw)) {
        os_printf("ip addr mismatch: " IPSTR "\n", IP2STR(ipaddr));
    }
    return icmp_net_linkoutput(netif, p);
}

static struct icmp_net_config *root = NULL;

err_t icmp_net_init(struct netif *netif) {
    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_POINTTOPOINT;
    netif->output = icmp_net_output;
    netif->linkoutput = netif->linkoutput;

    struct icmp_net_config *config = netif->state;
    config->next = root;
    config->netif = netif;
    root = config;

    return ERR_OK;
}

void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
    user_dprintf("icmp_input()\n");

    struct ip_hdr *iphdr = p->payload;
    s16_t hlen = IPH_HL(iphdr) * 4;
    if (p->tot_len < hlen + sizeof(u16_t) * 2) {
        user_dprintf("invalid ICMP: %d bytes\n", p->tot_len);
        return;
    }

    u8_t type = ((u8_t *)p->payload)[hlen];

    if (type == ICMP_ER) {
        pbuf_header(p, -hlen);

        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            extern ip_addr_t current_iphdr_src;

            user_dprintf("config=%p\n", config);
            if (ip_addr_cmp(&current_iphdr_src, &config->netif->gw)) {
                user_dprintf("match\n");
            }
        }
        pbuf_free(p);
        return;
    }

    __real_icmp_input(p, inp);
}
