#pragma once

#include <sys/time.h>
#include <linux/ip.h>
#include <stddef.h>
#include <set>

struct icmp_reply {
	icmp_reply(__be32 addr, unsigned short id, unsigned short seq);
	__be32 addr;
	unsigned short id, seq;
	struct timespec time;
};

bool operator<(const struct timespec &a, const struct timespec &b);
bool operator<(const icmp_reply &a, const icmp_reply &b);
