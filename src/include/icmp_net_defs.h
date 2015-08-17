#pragma once

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
