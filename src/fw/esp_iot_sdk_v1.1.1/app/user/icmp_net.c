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

#define L2_HLEN (PBUF_LINK_HLEN + IP_HLEN)
#define L3_HLEN (L2_HLEN + sizeof(struct icmp_echo_hdr))

static void process_pbuf(struct icmp_net_config *config, struct pbuf *p);
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p);

struct icmp_net_hdr {
    unsigned char queued;
};

static inline unsigned long ccount() {
    register unsigned long ccount;
    asm(
        "rsr.ccount %0"
        :"=r"(ccount)
    );
    return ccount;
}

static inline unsigned short timestamp() {
    return ccount() >> 16U;
}

ICACHE_FLASH_ATTR
static err_t send_keepalive(struct netif *netif) {
    ICMP_NET_CONFIG_UNLOCK(config);
    user_dprintf("sending keepalive");
    struct pbuf *p = pbuf_alloc(PBUF_RAW, L3_HLEN, PBUF_RAM);
    pbuf_header(p, (s16_t)-L3_HLEN);
    err_t ret = icmp_net_linkoutput(netif, p);
    ICMP_NET_CONFIG_LOCK(config);
    return ret;
}

/**
 * Drop recv_i.
 * Increment recv_i and process packets starting from recv_i.
 * config must be locked.
 */
ICACHE_FLASH_ATTR
static void drop_echo_reply(struct icmp_net_config *config) {
    assert(0 < ICMP_NET_CONFIG_QLEN(config));
    assert(ICMP_NET_CONFIG_QLEN(config) <= ICMP_NET_QSIZE);
    struct pbuf *p;
    while (config->recv_i != config->send_i && (p = config->queue[++config->recv_i % ICMP_NET_QSIZE])) {
        if (p == NULL) {
            break;
        }
        process_pbuf(config, p);
        user_dprintf("freeing %p with refcnt %u", p, p->ref);
        pbuf_free(p);

        ICMP_NET_CONFIG_UNLOCK(config);
        ICMP_NET_CONFIG_LOCK(config);
    }
}

ICACHE_FLASH_ATTR
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    struct icmp_net_config *config = netif->state;
    assert(config->slave);

    if (pbuf_header(p, L3_HLEN)) {
        struct pbuf *r = pbuf_alloc(PBUF_RAW, L3_HLEN + p->tot_len, PBUF_RAM);
        if (!r) {
            user_dprintf("no memory");
            pbuf_free(p);
            return ERR_MEM;
        }
        if (pbuf_header(r, (s16_t)-L3_HLEN)) {
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
        if (pbuf_header(r, L3_HLEN)) {
            user_dprintf("move to header failed");
            goto err_buf;
        }

        pbuf_free(p);
        p = r;
    }

send:
    if (pbuf_header(p, -L2_HLEN)) {
        user_dprintf("move to icmp header failed");
        pbuf_free(p);
        return ERR_BUF;
    }

    {
        struct icmp_echo_hdr *iecho = (struct icmp_echo_hdr *)p->payload;
        iecho->type = ICMP_ECHO;
        iecho->code = 0;
        iecho->chksum = 0;
        iecho->id = htons(timestamp());
        ICMP_NET_CONFIG_LOCK(config);
        if (ICMP_NET_CONFIG_QLEN(config) == ICMP_NET_QSIZE) {
            user_dprintf("dropping packet #%u", config->recv_i);
            drop_echo_reply(config);
        }
        assert(ICMP_NET_CONFIG_QLEN(config) < ICMP_NET_QSIZE);
        config->queue[config->send_i % ICMP_NET_QSIZE] = NULL;
        short seqno = config->send_i++;
        ICMP_NET_CONFIG_UNLOCK(config);
        iecho->seqno = htons(seqno);
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

    if (ICMP_NET_CONFIG_MUST_KEEPALIVE(config)) {
        user_dprintf("sending keepalive");
        p = pbuf_alloc(PBUF_RAW, L3_HLEN, PBUF_RAM);
        goto send;
    }

    return ERR_OK;
}

ICACHE_FLASH_ATTR
static err_t icmp_net_output(struct netif *netif, struct pbuf *p, struct ip_addr *dst) {
    return icmp_net_linkoutput(netif, p);
    user_dprintf("");
    return etharp_output(netif, p, dst);
}

static struct icmp_net_config *root = NULL;

/**
 * Process an input ping in pbuf.
 * config must be locked.
 */
ICACHE_FLASH_ATTR
static void process_pbuf(struct icmp_net_config *config, struct pbuf *p) {
    assert(config->slave);
    extern ip_addr_t current_iphdr_src;

    if (ip_addr_cmp(&current_iphdr_src, &config->relay_ip)) {
        user_dprintf("match: len=%u", p->tot_len);
        // TODO check header retransmission, delay
        (*config->slave->input)(p, config->slave);
    }
}

ICACHE_FLASH_ATTR
err_t icmp_net_init(struct netif *netif) {
    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_POINTTOPOINT | NETIF_FLAG_ETHARP;
    //netif->output = etharp_output;
    netif->output = icmp_net_output;
    netif->linkoutput = icmp_net_linkoutput;

    struct icmp_net_config *config = netif->state;
    config->netif = netif;
    config->next = root;
    config->slave = NULL;
    config->dhcp_bound_callback = NULL;
    config->send_i = config->recv_i = 0;
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
    if (p->tot_len < ip_hlen + icmp_hlen + sizeof(struct icmp_net_hdr)) {
        user_dprintf("short: %d bytes", p->tot_len);
        goto end;
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
        pbuf_header(p, -icmp_hlen);
        uint16_t seqno = ntohs(iecho->seqno);
        user_dprintf("echo reply: %u ms, seqno=%u", (((unsigned)(timestamp() - ntohs(iecho->id))) << 15U) / (500U * (unsigned)system_get_cpu_freq()), seqno);

        struct icmp_net_hdr *ihdr = p->payload;
        assert(sizeof(*ihdr) == 1);
        pbuf_header(p, (s16_t)-sizeof(*ihdr));

        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            ICMP_NET_CONFIG_LOCK(config);
            if (((unsigned)(seqno - config->recv_i)) < ((unsigned)(config->send_i - config->recv_i))) {
                if (config->recv_i == seqno) {
                    process_pbuf(config, p);
                    drop_echo_reply(config);
                } else {
                    struct pbuf **dst = &config->queue[seqno % ICMP_NET_QSIZE];
                    if (*dst) {
                        user_dprintf("duplicate packet %u", seqno);
                    } else {
                        pbuf_ref(p);
                        user_dprintf("saved %p with refcnt %u", p, p->ref);
                        *dst = p;
                    }
                }
            }
            ICMP_NET_CONFIG_UNLOCK(config);

            ICMP_NET_CONFIG_LOCK(config);
            int queued = seqno + ihdr->queued + 1 - config->send_i;
            user_dprintf("q len: %d, seqno: %d, queued: %d, send_i: %d", ICMP_NET_CONFIG_QLEN(config), seqno, queued, config->send_i);
            while (ICMP_NET_CONFIG_MUST_KEEPALIVE(config) || (queued && ICMP_NET_CONFIG_CAN_KEEPALIVE(config))) {
                if (queued) {
                    --queued;
                }
                if (send_keepalive(config->netif)) {
                    user_dprintf("fetch queued: error");
                    break;
                }
            }
            ICMP_NET_CONFIG_UNLOCK(config);
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
