#pragma once

#include <sys/time.h>
#include <linux/ip.h>
#include <stddef.h>
#include <set>
#include <boost/chrono.hpp>

struct icmp_reply {
	typedef boost::chrono::steady_clock boost_clock_t;
	icmp_reply(__be32 addr, unsigned short id, unsigned short seq);
	__be32 addr;
	unsigned short id, seq;
	boost_clock_t::time_point time;
};

bool operator<(const icmp_reply &a, const icmp_reply &b);
