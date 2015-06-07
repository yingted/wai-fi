#include "osapi.h"
#include "private_api.h"
#include "icmp_net.h"
#include "lwip/icmp.h"
#include "lwip/ip.h"
#include "lwip/netif.h"

static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    struct icmp_net_config *config = netif->state;
    user_dprintf("icmp_net_linkoutput()\n");

    const static u16_t hlen = IP_HLEN + sizeof(struct icmp_echo_hdr);
    if (pbuf_header(p, hlen)) {
        user_dprintf("icmp_net_linkoutput: resizing p\n");
        struct pbuf *r = pbuf_alloc(PBUF_RAW, hlen + p->tot_len, PBUF_RAM);
        if (!r) {
            user_dprintf("icmp_net_linkoutput: no memory\n");
            pbuf_free(p);
            return ERR_MEM;
        }
        if (pbuf_header(r, -hlen)) {
            user_dprintf("icmp_net_linkoutput: reserve header failed\n");
err_buf:
            pbuf_free(r);
            pbuf_free(p);
            return ERR_BUF;
        }
        if (pbuf_copy(r, p) != ERR_OK) {
            user_dprintf("icmp_net_linkoutput: copy failed");
            goto err_buf;
        }
        if (pbuf_header(r, hlen)) {
            user_dprintf("icmp_net_linkoutput: move to header failed\n");
            goto err_buf;
        }

        pbuf_free(p);
        p = r;
    }
    pbuf_header(p, -IP_HLEN);

    {
        u32_t header = 0; // TODO

        struct icmp_echo_hdr *icmphdr = (struct icmp_echo_hdr *)p->payload;
        icmphdr->type = ICMP_ECHO;
        icmphdr->code = 0;
        icmphdr->chksum = 0;
        ((u32_t *)icmphdr)[1] = header;
        icmphdr->chksum = inet_chksum(icmphdr, p->len);
    }

    {
        struct netif *slave = config->slave;
        ip_output_if(p, &slave->ip_addr, &slave->gw, ICMP_TTL, 0, IP_PROTO_ICMP, slave);
    }
    pbuf_free(p);
    return ERR_OK;
}

static err_t icmp_net_output(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr) {
    if (!ip_addr_cmp(ipaddr, &netif->gw)) {
        user_dprintf("ip addr mismatch: " IPSTR "\n", IP2STR(ipaddr));
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
    config->slave = netif_default;
    root = config;

    return ERR_OK;
}

void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
    user_dprintf("icmp_input()\n");

    struct ip_hdr *iphdr = p->payload;
    s16_t ip_hlen = IPH_HL(iphdr) * 4;
    const static s16_t icmp_hlen = sizeof(u32_t) * 2;
    if (p->tot_len < ip_hlen + icmp_hlen) {
        user_dprintf("icmp_input: short: %d bytes\n", p->tot_len);
        return;
    }

    u8_t type = ((u8_t *)p->payload)[ip_hlen];
    u16_t header = ((u32_t *)(((u8_t *)p->payload) + ip_hlen))[1];

    // Intercept ICMP echo replies.
    if (type == ICMP_ER) {
        pbuf_header(p, -ip_hlen);
        if (!inet_chksum_pbuf(p)) {
            user_dprintf("icmp_input: checksum failed\n");
            goto end;
        }

        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            extern ip_addr_t current_iphdr_src;

            user_dprintf("icmp_input: config=%p\n", config);
            if (ip_addr_cmp(&current_iphdr_src, &config->slave->gw)) {
                user_dprintf("icmp_input: match: header=%u len=%u\n", header, p->tot_len);
                // TODO check header retransmission
                (*config->slave->input)(p, config->slave);
            }
        }

end:
        pbuf_free(p);
        return;
    }

    __real_icmp_input(p, inp);
}
