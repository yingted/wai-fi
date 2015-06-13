#ifndef __INET_CHECKSUM_H__
#define __INET_CHECKSUM_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint16_t inet_checksum(void *begin, void *end);

#ifdef __cplusplus
}
#endif

#endif
