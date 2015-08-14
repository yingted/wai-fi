#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint16_t inet_checksum(void *begin, void *end);

#ifdef __cplusplus
}
#endif
