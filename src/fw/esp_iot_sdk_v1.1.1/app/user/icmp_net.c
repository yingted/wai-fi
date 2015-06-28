#include "user_config.h"
#include "osapi.h"
#include "private_api.h"
#include "c_types.h"
#include "icmp_net.h"
#include "lwip/icmp.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/netif/etharp.h"
#include <stddef.h>
#include "debug_esp.h"

// from user_interface.h:
#define STATION_IF      0x00

#define L2_HLEN (PBUF_LINK_HLEN + IP_HLEN)
#define L3_HLEN (L2_HLEN + sizeof(struct icmp_echo_hdr))

static void process_pbuf(struct icmp_net_config *config, struct pbuf *p);
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p);

struct icmp_net_hdr {
    unsigned char queued, pad_[3];
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
    user_dprintf("sending keepalive"); // TODO timeout
    struct pbuf *p = pbuf_alloc(PBUF_RAW, L3_HLEN, PBUF_RAM);
    if (p == NULL) {
        mem_error();
    }
    pbuf_header(p, (s16_t)-L3_HLEN);
    err_t ret = icmp_net_linkoutput(netif, p);
    ICMP_NET_CONFIG_LOCK(config);
    return ret;
}

/**
 * Drop recv_i. Usually, it was just processed.
 * Increment recv_i and process packets starting from recv_i, if they exist.
 * config must be locked.
 */
ICACHE_FLASH_ATTR
static void drop_echo_reply(struct icmp_net_config *config) {
    assert(0 < ICMP_NET_CONFIG_QLEN(config));
    assert(ICMP_NET_CONFIG_QLEN(config) <= ICMP_NET_QSIZE);
    assert_heap();
    struct pbuf *p;
    while (ICMP_NET_CONFIG_QLEN(config) > 0 && (p = config->queue[++config->recv_i % ICMP_NET_QSIZE])) {
        if (p == NULL) {
            break;
        }

#ifdef DEBUG_ESP
        user_dprintf("processing packet %d", config->recv_i);
#endif
        process_pbuf(config, p);
        pbuf_free(p);
    }
}

ICACHE_FLASH_ATTR
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    assert_heap();
    struct icmp_net_config *config = netif->state;
    assert(config->slave);
#ifdef DEBUG_ESP
    user_dprintf("%p %p", netif, p);
    user_dprintf("ref: %d, len: %d, tot_len: %d", p->ref, p->len, p->tot_len);
#endif
    assert(p->ref >= 1);
    assert(p->len < 2000);
    assert(p->tot_len < 2000);

    { // copy p
        assert(p->tot_len < 2000);
        struct pbuf *r = pbuf_alloc(PBUF_RAW, L3_HLEN + p->tot_len, PBUF_RAM);
        if (!r) {
            user_dprintf("no memory");
            mem_error();
            return ERR_MEM;
        }
        int i;
        for (i = 0; i < r->len; ++i)
            ((u8_t *)r->payload)[i] = '\x8f';
        if (pbuf_header(r, (s16_t)-L3_HLEN)) {
            user_dprintf("reserve header failed");
err_buf:
            pbuf_free(r);
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

        p = r;
    }

send:
    if (pbuf_header(p, -L2_HLEN)) {
        user_dprintf("move to icmp header failed");
        pbuf_free(p);
        return ERR_BUF;
    }

    {
        assert((((size_t)p->payload) & 0x1) == 0);
        struct icmp_echo_hdr *iecho = (struct icmp_echo_hdr *)p->payload;
        iecho->type = ICMP_ECHO;
        iecho->code = 0;
        iecho->chksum = 0;
        iecho->id = htons(timestamp());
        ICMP_NET_CONFIG_LOCK(config);
        if (ICMP_NET_CONFIG_QLEN(config) == ICMP_NET_QSIZE) {
            user_dprintf("drop packet #%u", config->recv_i);
            drop_echo_reply(config);
        }
        assert(ICMP_NET_CONFIG_QLEN(config) < ICMP_NET_QSIZE);
        config->queue[config->send_i % ICMP_NET_QSIZE] = NULL;
        short seqno = config->send_i++;
        ICMP_NET_CONFIG_UNLOCK(config);
        iecho->seqno = htons(seqno);
        iecho->chksum = inet_chksum(p->payload, p->len);
    }

    {
        struct netif *slave = config->slave;
#ifdef DEBUG_ESP
        user_dprintf("writing %u from " IPSTR " to " IPSTR, p->len - sizeof(struct icmp_echo_hdr), IP2STR(&slave->ip_addr), IP2STR(&config->relay_ip));
#endif
        //USER_INTR_LOCK();
        int lmacIsActive();
        assert(!lmacIsActive());
        err_t rc = ip_output_if(p, IP_ADDR_ANY, &config->relay_ip, ICMP_TTL, 0, IP_PROTO_ICMP, slave);
        //USER_INTR_UNLOCK();

        if (rc != ERR_OK) {
            user_dprintf("error: %d", rc);
            pbuf_free(p);
            return rc;
        }
    }
    pbuf_free(p);

    if (ICMP_NET_CONFIG_MUST_KEEPALIVE(config)) {
#ifdef DEBUG_ESP
        user_dprintf("sending keepalive");
#endif
        p = pbuf_alloc(PBUF_RAW, L3_HLEN, PBUF_RAM);
        if (p == NULL) {
            mem_error();
        }
        goto send;
    }

    assert_heap();
    return ERR_OK;
}

static struct icmp_net_config *root = NULL;
#define PROCESS_PBUF_QSIZE 4
struct pbuf *process_pbuf_q[PROCESS_PBUF_QSIZE] = {NULL, NULL, NULL, NULL};
struct icmp_net_config *process_pbuf_q_config[PROCESS_PBUF_QSIZE];

/**
 * Process an input ping in pbuf.
 * config must be locked.
 * p->ref neutral.
 */
ICACHE_FLASH_ATTR
static void process_pbuf(struct icmp_net_config *config, struct pbuf *p) {
    assert_heap();
    assert(config->slave);
    assert(p->ref >= 1);
    assert(p->len < 2000);
    assert(p->tot_len < 2000);
    extern ip_addr_t current_iphdr_src;

    if (ip_addr_cmp(&current_iphdr_src, &config->relay_ip)) {
#ifdef DEBUG_ESP
        assert(icmp_net_lwip_entry_count);
        user_dprintf("enqueuing len=%u", p->tot_len);
#endif
        pbuf_ref(p);
        int i;
        for (i = 0; i < PROCESS_PBUF_QSIZE; ++i) {
            assert((process_pbuf_q[i] == NULL) == (process_pbuf_q_config[i] == NULL));
            if (process_pbuf_q[i] == NULL) {
                process_pbuf_q[i] = p;
                process_pbuf_q_config[i] = config;
                break;
            }
        }
        if (i == PROCESS_PBUF_QSIZE) {
            user_dprintf("dropped ethernet frame");
        }
        if (ICMP_NET_CONFIG_QLEN(config) > 0) {
            drop_echo_reply(config);
        }
#ifdef DEBUG_ESP
        assert(icmp_net_lwip_entry_count);
#endif
    }
}

ICACHE_FLASH_ATTR
static void process_queued_pbufs() {
    assert_heap();
    USER_INTR_LOCK();
    while (process_pbuf_q[0]) {
        struct pbuf *p = process_pbuf_q[0];
        struct icmp_net_config *config = process_pbuf_q_config[0];
        int i;
        for (i = 0; i + 1 < PROCESS_PBUF_QSIZE; ++i) {
            process_pbuf_q[i] = process_pbuf_q[i + 1];
            process_pbuf_q_config[i] = process_pbuf_q_config[i + 1];
        }
        process_pbuf_q[i] = NULL;
        process_pbuf_q_config[i] = NULL;
        USER_INTR_UNLOCK();

        assert(p);
        assert(config);
#ifdef DEBUG_ESP
        user_dprintf("netif->input %d", p->tot_len);
#endif
        assert(p->ref == 1);

        err_t rc = config->netif->input(p, config->netif);
        if (rc != ERR_OK) {
            user_dprintf("netif->input: error %d", rc);
            pbuf_free(p);
        }
        USER_INTR_LOCK();
    }
    USER_INTR_UNLOCK();
    assert_heap();
}

ICACHE_FLASH_ATTR
err_t icmp_net_output(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr) {
    assert_heap();
    assert(p->tot_len < 2000);
    err_t ret = etharp_output(netif, p, ipaddr);
    assert_heap();
    return ret;
}

ICACHE_FLASH_ATTR
err_t icmp_net_init(struct netif *netif) {
    user_dprintf("");

    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_POINTTOPOINT | NETIF_FLAG_ETHARP;
    //netif->output = etharp_output;
    netif->output = icmp_net_output;
    netif->linkoutput = icmp_net_linkoutput;

    struct icmp_net_config *config = netif->state;
    config->netif = netif;
    config->slave = NULL;
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
                assert(0 <= i && i < 6);
                if (++last_hwaddr[i]) {
                    break;
                }
            }
        }
    }
    const char name[2] = {'i', 'n'};
    os_memcpy(netif->name, name, sizeof(name));
    static u8_t if_num = 0;
    netif->num = if_num++;
    netif->mtu = 1400; // TODO discover

    USER_INTR_LOCK();
    config->next = root;
    root = config;
    USER_INTR_UNLOCK();

    assert_heap();
    user_dprintf("done");

    return ERR_OK;
}

ICACHE_FLASH_ATTR
void icmp_net_enslave(struct icmp_net_config *config, struct netif *slave) {
    assert(config->netif != NULL);
    assert(slave != NULL);
    assert(config->slave == NULL);
    config->slave = slave;

    // TODO replace input
}

ICACHE_FLASH_ATTR
void icmp_net_unenslave(struct icmp_net_config *config) {
    assert(config->netif != NULL);
    assert(config->slave != NULL);
    config->slave = NULL;
}

err_t __real_ethernet_input(struct pbuf *p, struct netif *netif);
ICACHE_FLASH_ATTR
err_t __wrap_ethernet_input(struct pbuf *p, struct netif *netif) {
#ifdef DEBUG_ESP
    assert_heap();
    user_dprintf("%p %p", p, netif);
    assert(p->ref >= 1);
    assert(p->len < 2000);
    assert(p->tot_len < 2000);
    assert(icmp_net_lwip_entry_count++ == 0);
#endif
    err_t ret = __real_ethernet_input(p, netif);
#ifdef DEBUG_ESP
    assert(--icmp_net_lwip_entry_count == 0);
#endif
    process_queued_pbufs();
    return ret;
}

void __real_sys_check_timeouts(void);
ICACHE_FLASH_ATTR
void __wrap_sys_check_timeouts(void) {
#ifdef DEBUG_ESP
    assert_heap();
    assert(icmp_net_lwip_entry_count++ == 0);
#endif
    __real_sys_check_timeouts();
#ifdef DEBUG_ESP
    assert(--icmp_net_lwip_entry_count == 0);
#endif
    process_queued_pbufs();
}

void __real_icmp_input(struct pbuf *p, struct netif *inp);
ICACHE_FLASH_ATTR
void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
    user_dprintf("%p %p", p, inp);
    assert((((size_t)p->payload) & 0x1) == 0);
    assert(p->ref >= 1);
    assert(p->len < 2000);
    assert(p->tot_len < 2000);
    assert_heap();

    struct ip_hdr *iphdr = p->payload;
    s16_t ip_hlen = IPH_HL(iphdr) * 4;
    const static s16_t icmp_hlen = sizeof(u32_t) * 2;
    if (p->tot_len < ip_hlen + icmp_hlen + sizeof(struct icmp_net_hdr)) {
        user_dprintf("short: %d bytes", p->tot_len);
        {
            int i;
            os_printf("first %d bytes: ", p->len);
            for (i = 0; i < p->len; ++i) {
                os_printf("%02x", ((u8_t *)p->payload)[i]);
            }
            os_printf("\n");
        }
        goto end;
    }

    u8_t type = ((u8_t *)p->payload)[ip_hlen];

    // Intercept ICMP echo replies.
    if (type == ICMP_ER) {
        pbuf_header(p, -ip_hlen);
        assert((((size_t)p->payload) & 0x1) == 0);
        if (inet_chksum_pbuf(p)) {
            user_dprintf("checksum failed");
            goto end;
        }

        assert_heap();

        struct icmp_echo_hdr *iecho = p->payload;
        pbuf_header(p, -icmp_hlen);
        assert((((size_t)p->payload) & 0x1) == 0);
        uint16_t seqno = ntohs(iecho->seqno);
        user_dprintf("echo reply: %u ms, seqno=%u", (((unsigned)(timestamp() - ntohs(iecho->id))) << 15U) / (500U * (unsigned)system_get_cpu_freq()), seqno);

        struct icmp_net_hdr *ihdr = p->payload;
        pbuf_header(p, (s16_t)-sizeof(*ihdr));
        assert((((size_t)p->payload) & 0x1) == 0);

        assert_heap();

        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            assert_heap();
            ICMP_NET_CONFIG_LOCK(config);
            if (((unsigned)(seqno - config->recv_i)) < ((unsigned)(config->send_i - config->recv_i))) {
                user_dprintf("receive window [%u, %u)", config->recv_i, config->send_i);
                assert(p->ref >= 1);
                assert(p->len < 2000);
                assert(p->tot_len < 2000);
                if (config->recv_i == seqno) {
                    process_pbuf(config, p);
                } else {
                    struct pbuf **dst = &config->queue[seqno % ICMP_NET_QSIZE];
                    if (*dst) {
                        user_dprintf("duplicate packet %u", seqno);
                    } else {
                        pbuf_ref(p);
                        *dst = p;
                    }
                }
            }
            ICMP_NET_CONFIG_UNLOCK(config);

            ICMP_NET_CONFIG_LOCK(config);
            int queued = seqno + ihdr->queued + 1 - config->send_i;
            if (queued < 0) {
                queued = 0; // cannot queue negative
            }
            user_dprintf("qlen: %d, seqno: %d, queued: %d, send_i: %d", ICMP_NET_CONFIG_QLEN(config), seqno, queued, config->send_i);
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
        assert_heap();
        pbuf_free(p);
        return;
    }

    assert_heap();
    __real_icmp_input(p, inp);
    assert_heap();
}
