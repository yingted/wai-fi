#pragma once

// Must be a power of 2
#define ICMP_NET_QSIZE 16U
#define ICMP_NET_MAX_KEEPALIVE 8U
#define ICMP_NET_MIN_KEEPALIVE 2U
// TTL (3 means it survives 3 timeouts and dies on the 4th), in 500 ms units
#define ICMP_NET_MAX_JITTER ((1000 /* ms */) / DHCP_FINE_TIMER_MSECS - 1)
#define ICMP_NET_TTL ((30 * 1000 /* ms */) / DHCP_FINE_TIMER_MSECS - 1)

struct icmp_net_shared_hdr {
    uint16_t device_id;
};

struct icmp_net_out_hdr {
    struct icmp_net_shared_hdr hdr;
    uint16_t orig_seq;
};

struct icmp_net_in_hdr {
    struct icmp_net_shared_hdr hdr;
    unsigned char queued, pad_[1];
};
