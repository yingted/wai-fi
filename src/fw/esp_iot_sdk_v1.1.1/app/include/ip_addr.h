#ifndef __IP_ADDR_H__
#define __IP_ADDR_H__

#include <lwip/ip_addr.h>

struct ip_info {
    struct ip_addr ip;
    struct ip_addr netmask;
    struct ip_addr gw;
};

// From espressif/esp_wifi.h:
bool wifi_get_macaddr(uint8 if_index, uint8 *macaddr);

// We're missing a bunch of definitions
#define IP2STR(ipaddr) ip4_addr1_16(ipaddr), \
    ip4_addr2_16(ipaddr), \
    ip4_addr3_16(ipaddr), \
    ip4_addr4_16(ipaddr)

#define IPSTR "%d.%d.%d.%d"

#endif
