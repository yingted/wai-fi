#include "icmp_reply.h"

icmp_reply::icmp_reply(__be32 addr, unsigned short id, unsigned short seq) :
	addr(addr), id(id), seq(seq) {
	time = boost_clock_t::now();
}

static bool lt_seq(const icmp_reply &a, const icmp_reply &b) {
	return a.seq < b.seq;
}

bool operator<(const icmp_reply &a, const icmp_reply &b) {
	return lt_seq(a, b);
}
