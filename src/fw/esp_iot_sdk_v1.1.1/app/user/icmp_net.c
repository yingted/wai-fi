#include "user_config.h"
#include "osapi.h"
#include "private_api.h"
#include "c_types.h"
#include "icmp_net.h"
#include "lwip/icmp.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/netif/etharp.h"

// from user_interface.h:
#define STATION_IF      0x00

static inline unsigned long ccount() {
    register unsigned long ccount;
    asm(
        "rsr.ccount %0"
        :"=r"(ccount)
    );
    return ccount;
}

union ccount_header {
    u32_t header;
    struct packed_icmp {
        __packed u16_t id;
        __packed u16_t seqno;
    } icmp;
};

ICACHE_FLASH_ATTR
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    struct icmp_net_config *config = netif->state;

    const static u16_t l2_hlen = PBUF_LINK_HLEN + IP_HLEN;
    const static u16_t hlen = l2_hlen + sizeof(struct icmp_echo_hdr);
    if (pbuf_header(p, hlen)) {
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
    if (pbuf_header(p, -l2_hlen)) {
        user_dprintf("move to icmp header failed");
        pbuf_free(p);
        return ERR_BUF;
    }

    {
        struct icmp_echo_hdr *iecho = (struct icmp_echo_hdr *)p->payload;
        iecho->type = ICMP_ECHO;
        iecho->code = 0;
        iecho->chksum = 0;
        union ccount_header x = { .header = ccount() };
        iecho->id = htons(x.icmp.id);
        iecho->seqno = htons(x.icmp.seqno);
        iecho->chksum = inet_chksum(iecho, p->len);
    }

    {
        struct netif *slave = config->slave;
        user_dprintf("writing %u from " IPSTR " to " IPSTR, p->len, IP2STR(&slave->ip_addr), IP2STR(&config->relay_ip));
        err_t rc = ip_output_if(p, IP_ADDR_ANY, &config->relay_ip, ICMP_TTL, 0, IP_PROTO_ICMP, slave);

        if (rc != ERR_OK) {
            user_dprintf("error: %d", rc);
            pbuf_free(p);
            return rc;
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

ICACHE_FLASH_ATTR
static err_t icmp_net_output(struct netif *netif, struct pbuf *p, struct ip_addr *dst) {
    return icmp_net_linkoutput(netif, p);
    user_dprintf("");
    return etharp_output(netif, p, dst);
}

static struct icmp_net_config *root = NULL;

ICACHE_FLASH_ATTR
err_t icmp_net_init(struct netif *netif) {
    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_POINTTOPOINT | NETIF_FLAG_ETHARP;
    //netif->output = etharp_output;
    netif->output = icmp_net_output;
    netif->linkoutput = icmp_net_linkoutput;

    struct icmp_net_config *config = netif->state;
    config->next = root;
    config->slave = NULL;
    config->dhcp_bound_callback = NULL;
    {
        netif->hwaddr_len = 6;
        static u8_t *last_hwaddr = NULL;
        if (!last_hwaddr) {
            last_hwaddr = netif->hwaddr;
            assert(last_hwaddr);
            wifi_get_macaddr(STATION_IF, last_hwaddr);
            last_hwaddr[0] |= 2; // privately administered
        } else {
            int i = 6;
            os_memcpy(netif->hwaddr, last_hwaddr, i);
            last_hwaddr = netif->hwaddr;
            // increment the MAC address
            while (i--) {
                if (++last_hwaddr[i]) {
                    break;
                }
            }
            assert(0 <= i && i < 6);
        }
    }
    const char name[2] = {'i', 'n'};
    os_memcpy(netif->name, name, sizeof(name));
    static u8_t if_num = 0;
    netif->num = if_num++;
    netif->mtu = 1400; // TODO discover
    root = config;

    user_dprintf("ccount: %u", ccount());

    return ERR_OK;
}

ICACHE_FLASH_ATTR
void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
    user_dprintf("icmp_input()");

    struct ip_hdr *iphdr = p->payload;
    s16_t ip_hlen = IPH_HL(iphdr) * 4;
    const static s16_t icmp_hlen = sizeof(u32_t) * 2;
    if (p->tot_len < ip_hlen + icmp_hlen) {
        user_dprintf("short: %d bytes", p->tot_len);
        return;
    }

    u8_t type = ((u8_t *)p->payload)[ip_hlen];

    // Intercept ICMP echo replies.
    if (type == ICMP_ER) {
        pbuf_header(p, -ip_hlen);
        if (inet_chksum_pbuf(p)) {
            user_dprintf("checksum failed");
            goto end;
        }

        struct icmp_echo_hdr *iecho = p->payload;
        union ccount_header x = { .icmp = { .id = ntohs(iecho->id), .seqno = ntohs(iecho->seqno) } };
        user_dprintf("echo reply: %u ms", (ccount() - x.header) / 1000 / (unsigned)system_get_cpu_freq());

        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            extern ip_addr_t current_iphdr_src;

            user_dprintf("config=%p", config);
            if (ip_addr_cmp(&current_iphdr_src, &config->relay_ip)) {
                user_dprintf("match: len=%u", p->tot_len);
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

ICACHE_FLASH_ATTR
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

ICACHE_FLASH_ATTR
void icmp_net_set_dhcp_bound_callback(struct netif *netif, netif_status_callback_fn cb) {
    struct icmp_net_config *config = netif->state;
    config->dhcp_bound_callback = cb;
}
