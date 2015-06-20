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

// from user_interface.h:
#define STATION_IF      0x00

#define L2_HLEN (PBUF_LINK_HLEN + IP_HLEN)
#define L3_HLEN (L2_HLEN + sizeof(struct icmp_echo_hdr))

static void process_pbuf(struct icmp_net_config *config, struct pbuf *p);
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p);

void vPortFree(void *);

void show_esf_buf();
static bool is_mem_error = false;
ICACHE_FLASH_ATTR
static void mem_error() {
    is_mem_error = true;
    show_esf_buf();
    assert(false);
}

#define inet_chksum_pseudo __real_inet_chksum_pseudo
u16_t
__real_inet_chksum_pseudo(struct pbuf *p, 
       ip_addr_t *src, ip_addr_t *dest,
       u8_t proto, u16_t proto_len);
ICACHE_FLASH_ATTR
u16_t
__wrap_inet_chksum_pseudo(struct pbuf *p, 
       ip_addr_t *src, ip_addr_t *dest,
       u8_t proto, u16_t proto_len) {
    //user_dprintf("%p", p);
    return __real_inet_chksum_pseudo(p, src, dest, proto, proto_len);
}

#define inet_chksum_pseudo_partial __real_inet_chksum_pseudo_partial
u16_t
__real_inet_chksum_pseudo_partial(struct pbuf *p,
       ip_addr_t *src, ip_addr_t *dest,
       u8_t proto, u16_t proto_len, u16_t chksum_len);
ICACHE_FLASH_ATTR
u16_t
__wrap_inet_chksum_pseudo_partial(struct pbuf *p,
       ip_addr_t *src, ip_addr_t *dest,
       u8_t proto, u16_t proto_len, u16_t chksum_len) {
    //user_dprintf("%p", p);
    return __real_inet_chksum_pseudo_partial(p, src, dest, proto, proto_len, chksum_len);
}

#define inet_chksum __real_inet_chksum
u16_t
__real_inet_chksum(void *dataptr, u16_t len);
ICACHE_FLASH_ATTR
u16_t
__wrap_inet_chksum(void *dataptr, u16_t len) {
    //user_dprintf("%p", dataptr);
    return __real_inet_chksum(dataptr, len);
}

#define inet_chksum_pbuf __real_inet_chksum_pbuf
u16_t
__real_inet_chksum_pbuf(struct pbuf *p);
ICACHE_FLASH_ATTR
u16_t
__wrap_inet_chksum_pbuf(struct pbuf *p) {
    //user_dprintf("%p", p);
    return __real_inet_chksum_pbuf(p);
}

#define pvPort(Malloc) \
void *__real_pvPort ## Malloc(size_t size); \
ICACHE_FLASH_ATTR \
void *__wrap_pvPort ## Malloc(size_t size) { \
    void *ret = __real_pvPort ## Malloc(size); \
    if (!ret) { \
        user_dprintf("pvPort" #Malloc "(%u) failed", size); \
        mem_error(); \
    } \
    return ret; \
} \

#define pvPortMalloc __real_pvPortMalloc
pvPort(Malloc)
pvPort(Realloc)
pvPort(Zalloc)
pvPort(Calloc)

void *__real_esf_buf_alloc(long a, long b);
ICACHE_FLASH_ATTR
void *__wrap_esf_buf_alloc(long a, long b) {
    ets_intr_lock();
    void *ret = __real_esf_buf_alloc(a, b);
    ets_intr_unlock();
    user_dprintf("%ld %ld => %p", a, b, ret);
    if (!ret) {
        assert(false);
    }
    return ret;
}

void *__real_esf_rx_buf_alloc(long a, long b);
ICACHE_FLASH_ATTR
void *__wrap_esf_rx_buf_alloc(long a, long b) {
    ets_intr_lock();
    void *ret = __real_esf_rx_buf_alloc(a, b);
    ets_intr_unlock();
    //user_dprintf("%ld %ld => %p", a, b, ret);
    if (!ret) {
        assert(false);
    }
    return ret;
}

#define mem_malloc __real_mem_malloc
void *__real_mem_malloc(long a, long b);
ICACHE_FLASH_ATTR
void *__wrap_mem_malloc(long a, long b) {
    void *ret = __real_mem_malloc(a, b);
    if (!ret) {
        user_dprintf("%ld %ld", a, b);
        assert(false);
    }
    return ret;
}

#define mem_realloc __real_mem_realloc
void *__real_mem_realloc(long a, long b);
ICACHE_FLASH_ATTR
void *__wrap_mem_realloc(long a, long b) {
    void *ret = __real_mem_realloc(a, b);
    if (!ret) {
        user_dprintf("%ld %ld", a, b);
        assert(false);
    }
    return ret;
}

ICACHE_FLASH_ATTR
void show_esf_buf() {
    int lmacIsActive();
    os_printf("lmac: %d ", lmacIsActive());
    struct node {
        char data_[32];
        struct node *next;
    } **base = (struct node **)*((char ***)0x40101380), *cur;
    int i;
    os_printf("esf_buf:");
    for (i = 0; i < 5; ++i) { // esf_buf 1, 4, 5, 6, esf_rx_buf (in order)
        os_printf(" [%d", i);
        for (cur = base[i]; cur; cur = (((size_t)cur) & 0x3) ? NULL : cur->next) {
            os_printf(" %p", cur);
        }
        os_printf("]");
    }
    os_printf("\n");
{
    struct block {
        struct block *next;
        size_t size;
    };
    size_t heap_size = system_get_free_heap_size();
    size_t *addr = (void *)0x3ffe9e38;
    int i;
    static struct block *cur = NULL;
    if (is_mem_error && cur) {
        goto found;
    }
    void *ptr = pvPortMalloc(1);
    vPortFree(ptr);
    for (i = -1000; i <= 1000; ++i) {
        if (addr[i] == heap_size) {
            int j;
            void **it = (void *)(addr + i);
            for (j = -10; j <= 10; ++j) {
                if ((((char *)ptr) - 128) <= (char *)it[j] && (char *)it[j] <= ((char *)ptr) + 128) {
                    if (((struct block *)(it + j))->size == 0) {
                        cur = (void *)(it + j);
                        goto found;
                    }
                }
            }
        }
    }
    assert(false /* no heap */);
found:;
#if 0
    ets_intr_lock();
    os_printf("heap: %p size: %d blocks:", cur, heap_size);
    for (; cur != NULL && (3 & (size_t) cur) == 0; cur = cur->next) {
        os_printf(" [%d] %d", cur->size, ((size_t)cur->next) - (((size_t)cur) + cur->size));
        assert(cur->size <= 82000);
        assert(cur->next > cur);
        heap_size -= cur->size;
        if (((int)heap_size) <= 0) {
            break;
        }
    }
    os_printf("\n");
    assert(heap_size == 0);
    ets_intr_unlock();
#endif
}
}

struct icmp_net_hdr {
    unsigned char queued, pad_[3];
};

#define assert_heap() assert_heap_(__FILE__, __LINE__)
ICACHE_FLASH_ATTR
void assert_heap_(char *file, int line) {
    user_dprintf("%s:%d", file, line);
    uint32_t heap = system_get_free_heap_size();
    if (!(20000 <= heap && heap <= 50000)) {
        user_dprintf("heap: %d", heap);
        assert(false);
    }
    show_esf_buf();
}

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
 * Drop recv_i.
 * Increment recv_i and process packets starting from recv_i.
 * config must be locked.
 */
ICACHE_FLASH_ATTR
static void drop_echo_reply(struct icmp_net_config *config) {
    assert(0 < ICMP_NET_CONFIG_QLEN(config));
    assert(ICMP_NET_CONFIG_QLEN(config) <= ICMP_NET_QSIZE);
    assert_heap();
    struct pbuf *p;
    while (config->recv_i != config->send_i && (p = config->queue[++config->recv_i % ICMP_NET_QSIZE])) {
        if (p == NULL) {
            break;
        }
        process_pbuf(config, p);
        pbuf_free(p);

        ICMP_NET_CONFIG_UNLOCK(config);
        ICMP_NET_CONFIG_LOCK(config);
    }
}

ICACHE_FLASH_ATTR
static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    assert_heap();
    struct icmp_net_config *config = netif->state;
    assert(config->slave);

    {
        struct pbuf *r = pbuf_alloc(PBUF_RAW, L3_HLEN + p->tot_len, PBUF_RAM);
        if (!r) {
            user_dprintf("no memory");
            pbuf_free(p);
            mem_error();
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
        assert((((size_t)p->payload) & 0x3) == 0);
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
        iecho->chksum = inet_chksum(p->payload, p->len);
    }

    {
        struct netif *slave = config->slave;
        user_dprintf("writing %u from " IPSTR " to " IPSTR, p->len - sizeof(struct icmp_echo_hdr), IP2STR(&slave->ip_addr), IP2STR(&config->relay_ip));
        ets_intr_lock();
        int lmacIsActive();
        assert(!lmacIsActive());
        err_t rc = ip_output_if(p, IP_ADDR_ANY, &config->relay_ip, ICMP_TTL, 0, IP_PROTO_ICMP, slave);
        ets_intr_unlock();

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
        if (p == NULL) {
            mem_error();
        }
        goto send;
    }

    assert_heap();
    return ERR_OK;
}

static struct icmp_net_config *root = NULL;

/**
 * Process an input ping in pbuf.
 * config must be locked.
 */
ICACHE_FLASH_ATTR
static void process_pbuf(struct icmp_net_config *config, struct pbuf *p) {
    assert_heap();
    assert(config->slave);
    extern ip_addr_t current_iphdr_src;

    assert((((size_t)p->payload) & 0x3) == 0);
    if (ip_addr_cmp(&current_iphdr_src, &config->relay_ip)) {
        user_dprintf("match: len=%u", p->tot_len);
        err_t rc = config->netif->input(p, config->netif);
        if (rc != ERR_OK) {
            user_dprintf("netif->input: error %d", rc);
        }
    }
}

ICACHE_FLASH_ATTR
err_t icmp_net_init(struct netif *netif) {
    user_dprintf("");

    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_POINTTOPOINT | NETIF_FLAG_ETHARP;
    netif->output = etharp_output;
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

    ets_intr_lock();
    config->next = root;
    root = config;
    ets_intr_unlock();

    assert_heap();
    user_dprintf("done");

    return ERR_OK;
}

void __real_icmp_input(struct pbuf *p, struct netif *inp);
ICACHE_FLASH_ATTR
void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
    user_dprintf("%p %p", p, inp);
    assert((((size_t)p->payload) & 0x3) == 0);
    assert_heap();

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
        assert((((size_t)p->payload) & 0x3) == 0);
        if (inet_chksum_pbuf(p)) {
            user_dprintf("checksum failed");
            goto end;
        }

        assert_heap();

        struct icmp_echo_hdr *iecho = p->payload;
        pbuf_header(p, -icmp_hlen);
        assert((((size_t)p->payload) & 0x3) == 0);
        uint16_t seqno = ntohs(iecho->seqno);
        user_dprintf("echo reply: %u ms, seqno=%u", (((unsigned)(timestamp() - ntohs(iecho->id))) << 15U) / (500U * (unsigned)system_get_cpu_freq()), seqno);

        struct icmp_net_hdr *ihdr = p->payload;
        pbuf_header(p, (s16_t)-sizeof(*ihdr));
        assert((((size_t)p->payload) & 0x3) == 0);

        assert_heap();

        struct icmp_net_config *config;
        for (config = root; config; config = config->next) {
            assert_heap();
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
