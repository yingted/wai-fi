#pragma once

#include "types.h"
#include <sys/time.h>
#include <linux/ip.h>
#include <stddef.h>
#include <set>
#include <boost/chrono.hpp>

struct icmp_reply {
	icmp_reply(__be32 addr, unsigned short id, unsigned short seq);
	__be32 addr;
	unsigned short id, seq;
	time_point_t time;
};
