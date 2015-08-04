#ifndef __IP_ADDR_H__
#define __IP_ADDR_H__

#include <lwip/ip_addr.h>

struct ip_info {
    struct ip_addr ip;
    struct ip_addr netmask;
    struct ip_addr gw;
};

#include <espressif/esp_misc.h>

#endif
