#include "osapi.h"
#include "private_api.h"
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

static err_t icmp_net_linkoutput(struct netif *netif, struct pbuf *p) {
    struct icmp_net_config *config = netif->state;
    user_dprintf("");

    const static u16_t hlen = IP_HLEN + sizeof(struct icmp_echo_hdr);
    if (pbuf_header(p, hlen)) {
        user_dprintf("resizing p to hold %u", (unsigned)(hlen + p->tot_len));
        struct pbuf *r = pbuf_alloc(PBUF_RAW, hlen + p->tot_len, PBUF_RAM);
        user_dprintf("resized: %p", r);
        if (!r) {
            user_dprintf("no memory");
            pbuf_free(p);
            return ERR_MEM;
        }
        user_dprintf("reserving header");
        if (pbuf_header(r, -hlen)) {
            user_dprintf("reserve header failed");
err_buf:
            pbuf_free(r);
            pbuf_free(p);
            return ERR_BUF;
        }
        user_dprintf("copying");
        if (pbuf_copy(r, p) != ERR_OK) {
            user_dprintf("copy failed");
            goto err_buf;
        }
        user_dprintf("moving to header");
        if (pbuf_header(r, hlen)) {
            user_dprintf("move to header failed");
            goto err_buf;
        }

        user_dprintf("freeing old p");
        pbuf_free(p);
        p = r;
    }
    user_dprintf("moving to icmp header");
    if (pbuf_header(p, -IP_HLEN)) {
        user_dprintf("move to icmp header failed");
        pbuf_free(p);
        return ERR_BUF;
    }

    {
        struct icmp_echo_hdr *icmphdr = (struct icmp_echo_hdr *)p->payload;
        user_dprintf("writing icmp header %p", icmphdr);
        icmphdr->type = ICMP_ECHO;
        icmphdr->code = 0;
        icmphdr->chksum = 0;
        ((u32_t *)icmphdr)[1] = ccount();
        icmphdr->chksum = inet_chksum(icmphdr, p->len);
    }

    user_dprintf("writing out packet");
    {
        struct netif *slave = config->slave;
        user_dprintf("writing to slave %p", slave);
        user_dprintf("writing %p from " IPSTR " to " IPSTR " ttl %u to %p", p, IP2STR(&slave->ip_addr), IP2STR(&config->relay_ip), (unsigned)ICMP_TTL, slave);
        err_t rc = ip_output_if(p, &slave->ip_addr, &config->relay_ip, ICMP_TTL, 0, IP_PROTO_ICMP, slave);
        if (rc != ERR_OK) {
            pbuf_free(p);
            return rc;
        }
    }
    user_dprintf("freeing p");
    pbuf_free(p);
    user_dprintf("done");
    return ERR_OK;
}

static err_t icmp_net_output(struct netif *netif, struct pbuf *p, struct ip_addr *dst) {
    user_dprintf("");
    return etharp_output(netif, p, dst);
}

static struct icmp_net_config *root = NULL;

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
            if (ip_addr_cmp(&current_iphdr_src, &config->relay_ip)) {
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

#include "lwip/udp.h"

struct udp_pcb *__real_udp_new(void);
struct udp_pcb *__wrap_udp_new(void) {
    user_dprintf("wrap");
    struct udp_pcb *ret = __real_udp_new();
    user_dprintf("return");
    return ret;
}

void __real_udp_remove(struct udp_pcb *pcb);
void __wrap_udp_remove(struct udp_pcb *pcb) {
    user_dprintf("wrap");
    __real_udp_remove(pcb);
    user_dprintf("return");
}

err_t __real_udp_bind(struct udp_pcb *pcb, ip_addr_t *ipaddr, u16_t port);
err_t __wrap_udp_bind(struct udp_pcb *pcb, ip_addr_t *ipaddr, u16_t port) {
    user_dprintf("wrap");
    err_t ret = __real_udp_bind(pcb, ipaddr, port);
    user_dprintf("return");
    return ret;
}

err_t __real_udp_connect(struct udp_pcb *pcb, ip_addr_t *ipaddr, u16_t port);
err_t __wrap_udp_connect(struct udp_pcb *pcb, ip_addr_t *ipaddr, u16_t port) {
    user_dprintf("wrap");
    err_t ret = __real_udp_connect(pcb, ipaddr, port);
    user_dprintf("return");
    return ret;
}

struct udp_pcb *__real_udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg);
struct udp_pcb *__wrap_udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg) {
    user_dprintf("wrap");
    struct udp_pcb *ret = __real_udp_recv(pcb, recv, recv_arg);
    user_dprintf("return");
    return ret;
}

err_t __real_udp_sendto_if(struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *dst_ip, u16_t dst_port, struct netif *netif);
err_t __wrap_udp_sendto_if(struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *dst_ip, u16_t dst_port, struct netif *netif) {
    user_dprintf("wrap");
    err_t ret = __real_udp_sendto_if(pcb, p, dst_ip, dst_port, netif);
    user_dprintf("return");
    return ret;
}
