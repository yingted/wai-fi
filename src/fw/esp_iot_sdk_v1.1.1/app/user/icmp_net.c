#include "osapi.h"
#include "private_api.h"
#include "icmp_net.h"
#include "lwip/icmp.h"
#include "lwip/ip.h"
#include "lwip/netif.h"

static inline unsigned long ccount() {
    register unsigned long ccount;
    asm(
        "rsr.ccount %0"
        :"=r"(ccount)
    );
    return ccount;
}

static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    struct icmp_net_config *config = netif->state;
    user_dprintf("");

    const static u16_t hlen = IP_HLEN + sizeof(struct icmp_echo_hdr);
    if (pbuf_header(p, hlen)) {
        user_dprintf("resizing p");
        struct pbuf *r = pbuf_alloc(PBUF_RAW, hlen + p->tot_len, PBUF_RAM);
        if (!r) {
            user_dprintf("no memory");
            pbuf_free(p);
            return ERR_MEM;
        }
        if (pbuf_header(r, -hlen)) {
            user_dprintf("reserve header failed");
err_buf:
            pbuf_free(r);
            pbuf_free(p);
            return ERR_BUF;
        }
        if (pbuf_copy(r, p) != ERR_OK) {
            user_dprintf("copy failed");
            goto err_buf;
        }
        if (pbuf_header(r, hlen)) {
            user_dprintf("move to header failed");
            goto err_buf;
        }

        pbuf_free(p);
        p = r;
    }
    pbuf_header(p, -IP_HLEN);

    {
        struct icmp_echo_hdr *icmphdr = (struct icmp_echo_hdr *)p->payload;
        icmphdr->type = ICMP_ECHO;
        icmphdr->code = 0;
        icmphdr->chksum = 0;
        ((u32_t *)icmphdr)[1] = ccount();
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
        user_dprintf("ip addr mismatch: " IPSTR, IP2STR(ipaddr));
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
    config->dhcp_bound_callback = NULL;
    root = config;

    user_dprintf("ccount: %u", ccount());

    return ERR_OK;
}

void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
    user_dprintf("icmp_input()");
    user_dprintf("ccount: %u", ccount());

    struct ip_hdr *iphdr = p->payload;
    s16_t ip_hlen = IPH_HL(iphdr) * 4;
    const static s16_t icmp_hlen = sizeof(u32_t) * 2;
    if (p->tot_len < ip_hlen + icmp_hlen) {
        user_dprintf("short: %d bytes", p->tot_len);
        return;
    }

    u8_t type = ((u8_t *)p->payload)[ip_hlen];
    u16_t header = ((u32_t *)(((u8_t *)p->payload) + ip_hlen))[1];

    // Intercept ICMP echo replies.
    if (type == ICMP_ER) {
        pbuf_header(p, -ip_hlen);
        if (!inet_chksum_pbuf(p)) {
            user_dprintf("checksum failed");
            goto end;
        }

        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            extern ip_addr_t current_iphdr_src;

            user_dprintf("config=%p", config);
            if (ip_addr_cmp(&current_iphdr_src, &config->slave->gw)) {
                user_dprintf("match: header=%u delay=%u freq=%u len=%u", header, ccount() - header, (unsigned int)system_get_cpu_freq(), p->tot_len);
                // TODO check header retransmission, delay
                (*config->slave->input)(p, config->slave);
            }
        }

end:
        pbuf_free(p);
        return;
    }

    __real_icmp_input(p, inp);
}

void __wrap_netif_set_up(struct netif *netif) {
    bool do_callback = !(netif->flags & NETIF_FLAG_UP);
    __real_netif_set_up(netif);
    if (do_callback) {
        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            if (config == netif->state && config->dhcp_bound_callback) {
                (*config->dhcp_bound_callback)(netif);
                break;
            }
        }
    }
}

void icmp_net_set_dhcp_bound_callback(struct netif *netif, netif_status_callback_fn cb) {
    struct icmp_net_config *config = netif->state;
    config->dhcp_bound_callback = cb;
}
