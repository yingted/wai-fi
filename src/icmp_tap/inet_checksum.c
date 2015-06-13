#include "inet_checksum.h"

uint16_t inet_checksum(void *begin, void *end) {
	uint32_t sum = ((char *)end - (char *)begin) & 1 ? ((uint8_t *)end)[-1] : 0;
	for (uint16_t *it = (uint16_t *)begin; (char *)it < (char *)end - 1; sum = (sum >> 16) + (uint16_t)sum) {
		sum += *it++;
	}
	return ~sum;
}
