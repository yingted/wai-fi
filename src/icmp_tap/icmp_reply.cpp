#include "icmp_reply.h"

bool operator<(const struct timespec &a, const struct timespec &b) {
	if (a.tv_sec != b.tv_sec) {
		return a.tv_sec < b.tv_sec;
	}
	return a.tv_nsec < b.tv_nsec;
}

static bool lt_seq(const icmp_reply &a, const icmp_reply &b) {
	return a.seq < b.seq;
}

bool operator<(const icmp_reply &a, const icmp_reply &b) {
	return lt_seq(a, b);
}
