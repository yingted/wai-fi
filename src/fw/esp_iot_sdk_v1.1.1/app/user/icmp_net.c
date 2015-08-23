#include <user_config.h>
#include <osapi.h>
#include <private_api.h>
#include <c_types.h>
#include <icmp_net.h>
#include <lwip/icmp.h>
#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/netif/etharp.h>
#include <lwip/inet_chksum.h>
#include <stddef.h>
#include <debug_esp.h>
#include <icmp_net_defs.h>

// from user_interface.h:
#define STATION_IF      0x00

#ifdef DEBUG_ESP
static int icmp_net_lwip_entry_count = 0;
#define ICMP_NET_LWIP_ENTER() assert(icmp_net_lwip_entry_count++ == 0)
#define ICMP_NET_LWIP_EXIT() assert(--icmp_net_lwip_entry_count == 0)
#define ICMP_NET_LWIP_ASSERT() assert(icmp_net_lwip_entry_count == 1)
#else
#define ICMP_NET_LWIP_ENTER()
#define ICMP_NET_LWIP_EXIT()
#define ICMP_NET_LWIP_ASSERT()
#endif

#define L2_HLEN (PBUF_LINK_HLEN + IP_HLEN)
#define L3_HLEN (L2_HLEN + sizeof(struct icmp_echo_hdr))

#define TOT_HLEN (s16_t)(L3_HLEN + sizeof(struct icmp_net_out_hdr))

static void process_pbuf(struct icmp_net_config *config, struct pbuf *p);
static void process_queued_pbufs();
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p);
static void packet_reply_timeout();

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
    err_t ret = icmp_net_linkoutput(netif, NULL);
    ICMP_NET_CONFIG_LOCK(config);
    return ret;
}

void __real_dhcp_fine_tmr();
ICACHE_FLASH_ATTR
void __wrap_dhcp_fine_tmr() {
    packet_reply_timeout();
    __real_dhcp_fine_tmr();
}

/**
 * Drop recv_i. Usually, it was just processed.
 * Increment recv_i and process packets starting from recv_i, if they exist.
 * config must be locked.
 */
ICACHE_FLASH_ATTR
static void drop_echo_reply(struct icmp_net_config *config) {
    assert(ICMP_NET_CONFIG_QLEN(config) > 0);
    assert(ICMP_NET_CONFIG_QLEN(config) <= ICMP_NET_QSIZE);
    assert_heap();
    struct pbuf *p;
    while ((p = config->queue[++config->recv_i % ICMP_NET_QSIZE])) {
        if (ICMP_NET_CONFIG_QLEN(config) == 0) {
            // We've just dropped the last outstanding packet, so there's nothing left to process
            // A keepalive must be sent
            break;
        }
        assert(ICMP_NET_CONFIG_QLEN(config) > 0);

#ifdef DEBUG_ESP
        user_dprintf("processing packet %p len=%d seq=%d", p, p->tot_len, config->recv_i);
#endif
        process_pbuf(config, p);
        pbuf_free(p);
        // We could have dropped packets in process_pbuf
        if (ICMP_NET_CONFIG_QLEN(config) == 0) {
            break;
        }
    }
    assert(ICMP_NET_CONFIG_QLEN(config) >= 0);
}

ICACHE_FLASH_ATTR
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    assert_heap();
    struct icmp_net_config *config = netif->state;
    assert(config->slave);
#ifdef DEBUG_ESP
    user_dprintf("%p %p", netif, p);
    if (p != NULL) {
        user_dprintf("ref: %d, len: %d, tot_len: %d", p->ref, p->len, p->tot_len);
    }
#endif
    if (p != NULL) {
        assert(p->ref >= 1);
        assert(p->len < 2000);
        assert(p->tot_len < 2000);
    }

    struct icmp_net_out_hdr *hdr;
copy:
    { // copy p
        assert(p == NULL || p->tot_len < 2000);
        struct pbuf *r = pbuf_alloc(PBUF_RAW, TOT_HLEN + (p == NULL ? 0 : p->tot_len), PBUF_RAM);
        if (!r) {
            user_dprintf("no memory");
            mem_error();
            return ERR_MEM;
        }
        hdr = (struct icmp_net_out_hdr *)(((char *)r->payload) + L3_HLEN);
        if (pbuf_header(r, -TOT_HLEN)) {
            user_dprintf("reserve header failed");
err_buf:
            pbuf_free(r);
            return ERR_BUF;
        }
        if (p != NULL && pbuf_copy(r, p) != ERR_OK) {
            user_dprintf("copy failed");
            goto err_buf;
        }
        if (pbuf_header(r, TOT_HLEN)) {
            user_dprintf("move to header failed");
            goto err_buf;
        }

        p = r;
    }

    assert(p != NULL);

    if (pbuf_header(p, -L2_HLEN)) {
        user_dprintf("move to icmp header failed");
        pbuf_free(p);
        return ERR_BUF;
    }

    unsigned short seqno;
    {
        assert((((size_t)p->payload) & 0x1) == 0);
        struct icmp_echo_hdr *iecho = (struct icmp_echo_hdr *)p->payload;
        iecho->type = ICMP_ECHO;
        iecho->code = 0;
        iecho->chksum = 0;
        iecho->id = htons(config->icmp_id);
        ICMP_NET_CONFIG_LOCK(config);
        if (ICMP_NET_CONFIG_QLEN(config) == ICMP_NET_QSIZE) {
            user_dprintf("drop packet #%u", config->recv_i);
            drop_echo_reply(config);
        }
        assert(ICMP_NET_CONFIG_QLEN(config) >= 0);
        assert(ICMP_NET_CONFIG_QLEN(config) < ICMP_NET_QSIZE);
        int index = config->send_i % ICMP_NET_QSIZE;
        config->queue[index] = NULL;
        config->ttl[index] = ICMP_NET_TTL;
        seqno = config->send_i++;
        ICMP_NET_CONFIG_UNLOCK(config);
        hdr->hdr.device_id = htons(icmp_net_device_id);
        hdr->orig_seq = iecho->seqno = htons(seqno);
        iecho->chksum = inet_chksum(p->payload, p->len);
    }

    {
        struct netif *slave = config->slave;
        user_dprintf("writing %u from " IPSTR " to " IPSTR " seq=%u", p->len - sizeof(struct icmp_echo_hdr) - sizeof(struct icmp_net_out_hdr), IP2STR(&slave->ip_addr), IP2STR(&config->relay_ip), seqno);
        //USER_INTR_LOCK();
#ifdef DEBUG_ESP
        int lmacIsActive();
        assert(!lmacIsActive());
#endif
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
        user_dprintf("sending keepalive");
        p = NULL;
        goto copy;
    }

    assert_heap();
    return ERR_OK;
}

static struct icmp_net_config *root = NULL;
#define PROCESS_PBUF_QSIZE ((ICMP_NET_QSIZE) + 1)
struct pbuf *process_pbuf_q[PROCESS_PBUF_QSIZE] = {0};
struct icmp_net_config *process_pbuf_q_config[PROCESS_PBUF_QSIZE];

/**
 * Process an input ping in pbuf with seq=config->recv_i.
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
    assert(ICMP_NET_CONFIG_QLEN(config) > 0);
    extern ip_addr_t current_iphdr_src;

    if (ip_addr_cmp(&current_iphdr_src, &config->relay_ip)) {
        ICMP_NET_LWIP_ASSERT();
        user_dprintf("enqueuing %p len=%u", p, p->tot_len);
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
        drop_echo_reply(config);
        ICMP_NET_LWIP_ASSERT();
    }
}

__attribute__((weak))
ICACHE_FLASH_ATTR
void icmp_net_process_queued_pbufs_callback() {
    // Do nothing
}

ICACHE_FLASH_ATTR
static void process_queued_pbufs() {
    icmp_net_process_queued_pbufs_callback();
    //assert_heap();
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
        user_dprintf("netif->input %p len=%d", p, p->tot_len);
        assert(p->ref >= 1);
        assert(config->netif->input == ethernet_input);

        err_t rc = config->netif->input(p, config->netif);
        if (rc != ERR_OK) {
            user_dprintf("netif->input: error %d", rc);
            pbuf_free(p);
        }
        USER_INTR_LOCK();
    }
    USER_INTR_UNLOCK();
    //assert_heap();
    icmp_net_process_queued_pbufs_callback();
}

ICACHE_FLASH_ATTR
static void packet_reply_timeout() {
    struct icmp_net_config *config;
    for (config = root; config; config = config->next) {
        ICMP_NET_CONFIG_LOCK(config);
        if (ICMP_NET_CONFIG_QLEN(config) > 0) {
            uint16_t i;
#ifndef NDEBUG
            bool retained_any = false;
#endif
            // TTL values are monotonically increasing.
            // If the next packet is timing out, drop this one.
            // This is because we have n+1 packets but only n TTL values.
            uint16_t pending_i = config->recv_i;
            for (i = config->recv_i + 1; i != config->send_i; ++i) {
                if (config->queue[i % ICMP_NET_QSIZE] != NULL) {
                    pending_i = i;
                }
                if ((uint16_t)(i + 1) != config->send_i) {
                    assert(config->ttl[i % ICMP_NET_QSIZE] <= config->ttl[(i + 1) % ICMP_NET_QSIZE]);
                }
            }
            // Everything after pending_i is NULL
            // Start at first packet not received.
            uint16_t timeout_ttl = ICMP_NET_TTL - ICMP_NET_MAX_JITTER;
            for (i = config->recv_i; (uint16_t)(i + 1) != config->send_i;) {
                if (i == pending_i) {
                    // i + 1 onwards all NULL, update the TTL
                    timeout_ttl = 0;
                }
                unsigned char next_ttl = config->ttl[(i + 1) % ICMP_NET_QSIZE]--;
                if (i == config->recv_i && next_ttl <= timeout_ttl) {
                    user_dprintf("timing out packet %u next_ttl=%u timeout_ttl=%u", i, next_ttl, timeout_ttl);
                    assert(!retained_any);
                    drop_echo_reply(config);
                    // Look at the (updated) first packet not received.
                    // Since we skipped a bunch of packets, we need to do a
                    // range check for the 2 invariants (for i and timeout_ttl).
                    // TODO use math
                    while (++i != config->recv_i) {
                        if (i == pending_i) {
                            timeout_ttl = 0;
                        }
                    }
                    // Now, i == config->recv_i, which is what we want.
                    // We want to skip the last packet. The first for loop only
                    // checks i + 1, not i.
                    if (i == config->send_i) {
                        break;
                    }
                    continue;
                }
#ifndef NDEBUG
                retained_any = true;
#endif
                // Look at the next packet. It's not the one we're waiting for.
                ++i;
            }
        }

        // TODO use a better way to check if the interface is active
        if (config->slave != NULL) {
            while (ICMP_NET_CONFIG_MUST_KEEPALIVE(config)) {
                if (send_keepalive(config->netif)) {
                    user_dprintf("fetch queued: error");
                    break;
                }
            }
        }
        ICMP_NET_CONFIG_UNLOCK(config);
    }
}

ICACHE_FLASH_ATTR
static err_t icmp_net_output(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr) {
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
    os_get_random((unsigned char *)&config->icmp_id, sizeof(config->icmp_id));
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
    _Static_assert(offsetof(struct netif, dhcp) == 32, "Not ABI v1.2.0 compatible");
    _Static_assert(offsetof(struct netif, mtu) == 44, "Not ABI v1.2.0 compatible");
    _Static_assert(offsetof(struct netif, hwaddr_len) == 46, "Not ABI v1.2.0 compatible");
    _Static_assert(offsetof(struct netif, hwaddr) == 47, "Not ABI v1.2.0 compatible");
    _Static_assert(offsetof(struct netif, flags) == 53, "Not ABI v1.2.0 compatible");

    USER_INTR_LOCK();
    config->next = root;
    root = config;
    USER_INTR_UNLOCK();

    //assert_heap(); // esf_buf not initialized
    user_dprintf("done");

    return ERR_OK;
}

ICACHE_FLASH_ATTR
static err_t my_ethernet_input(struct pbuf *p, struct netif *netif) {
#ifdef DEBUG_ESP
    assert_heap();
    user_dprintf("%p %p", p, netif);
    assert(p->ref >= 1);
    assert(p->len < 2000);
    assert(p->tot_len < 2000);
#endif
    ICMP_NET_LWIP_ENTER();
    err_t ret = ethernet_input(p, netif);
    ICMP_NET_LWIP_EXIT();
    if (ret != ERR_OK) {
        user_dprintf("ethernet_input: returned error %d", ret);
    }
    process_queued_pbufs();
    return ret;
}

ICACHE_FLASH_ATTR
void icmp_net_enslave(struct icmp_net_config *config, struct netif *slave) {
    ICMP_NET_CONFIG_LOCK(config);
    assert(slave != NULL);
    assert(slave->input == ethernet_input);
    slave->input = my_ethernet_input;

    assert(config->netif != NULL);
    assert(config->slave == NULL);
    config->slave = slave;
    ICMP_NET_CONFIG_UNLOCK(config);
}

ICACHE_FLASH_ATTR
void icmp_net_unenslave(struct icmp_net_config *config) {
    ICMP_NET_CONFIG_LOCK(config);
    struct netif *slave = config->slave;

    assert(config->netif != NULL);
    assert(slave != NULL);
    config->slave = NULL;

    assert(slave->input = my_ethernet_input);
    slave->input = ethernet_input;
    ICMP_NET_CONFIG_UNLOCK(config);
}

void __real_sys_check_timeouts(void);
ICACHE_FLASH_ATTR
void __wrap_sys_check_timeouts(void) {
    ICMP_NET_LWIP_ENTER();
    __real_sys_check_timeouts();
    ICMP_NET_LWIP_EXIT();
    process_queued_pbufs();
}

// XXX steal raw_input to guarantee etharp, etc.
static size_t icmp_input_entry_count = 0;
void __real_icmp_input(struct pbuf *p, struct netif *inp);
ICACHE_FLASH_ATTR
void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
    assert(icmp_input_entry_count++ == 0);
    assert((((size_t)p->payload) & 0x1) == 0);
    assert(p->ref >= 1);
    assert(p->len < 2000);
    assert(p->tot_len < 2000);
    assert_heap();

    struct ip_hdr *iphdr = p->payload;
    s16_t ip_hlen = IPH_HL(iphdr) * 4;
    const static s16_t icmp_hlen = sizeof(u32_t) * 2;
    _Static_assert(sizeof(struct icmp_net_out_hdr) == 4, "Incorrect header size");
    if (p->tot_len < ip_hlen + icmp_hlen + sizeof(struct icmp_net_in_hdr)) {
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
    if (type != ICMP_ER) {
        goto skip;
    }

    {
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
        user_dprintf("echo reply: seqno=%u", seqno);

        struct icmp_net_in_hdr *ihdr = p->payload;
        if (ihdr->hdr.device_id != htons(icmp_net_device_id)) {
            pbuf_header(p, ip_hlen + icmp_hlen);
            goto skip;
        }
        pbuf_header(p, (s16_t)-sizeof(*ihdr));
        assert((((size_t)p->payload) & 0x1) == 0);

        assert_heap();

        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            assert_heap();
            if (iecho->id != htons(config->icmp_id)) {
                user_dprintf("echo id %u doesn't match", ntohs(iecho->id));
                continue;
            }
            ICMP_NET_CONFIG_LOCK(config);
            assert(ICMP_NET_CONFIG_QLEN(config) >= 0);
            user_dprintf("receive window [%u, %u)", config->recv_i, config->send_i);
            if (((unsigned)(seqno - config->recv_i)) < ((unsigned)(config->send_i - config->recv_i))) {
                assert(p->ref >= 1);
                assert(p->len < 2000);
                assert(p->tot_len < 2000);
                if (config->recv_i == seqno) {
                    process_pbuf(config, p);
                } else {
                    int index = seqno % ICMP_NET_QSIZE;
                    struct pbuf **dst = &config->queue[index];
                    if (*dst) {
                        user_dprintf("duplicate packet %u", seqno);
                    } else {
                        // Copy to ram
                        struct pbuf *q = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
                        assert(q != NULL);
                        if (pbuf_copy(q, p)) {
                            assert(false);
                        }
                        *dst = q;
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
        assert(--icmp_input_entry_count == 0);
        return;
    }

skip:
    assert_heap();
    __real_icmp_input(p, inp);
    assert_heap();
    assert(--icmp_input_entry_count == 0);
}
