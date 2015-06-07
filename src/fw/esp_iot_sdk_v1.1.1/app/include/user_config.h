#ifndef __USER_CONFIG_H__
#define __USER_CONFIG_H__

#ifdef NDEBUG
#define user_dprintf(...)
#else
#define user_dprintf os_printf
#endif

#include "ip_addr.h"
#define LWIP_OPEN_SRC

#endif

