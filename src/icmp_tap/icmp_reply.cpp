#include "icmp_reply.h"

icmp_reply::icmp_reply(__be32 addr, unsigned short id, unsigned short seq) :
	addr(addr), id(id), seq(seq), time(boost_clock_t::now()), consumed(false), assembled(false) {
}
