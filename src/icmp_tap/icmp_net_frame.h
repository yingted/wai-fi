#pragma once

#include "types.h"
#include "icmp_reply.h"
#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <iostream>

typedef struct connection_id_ {
	uint16_t icmp_id, device_id;
} connection_id;

bool operator<(const connection_id &a, const connection_id &b);
std::ostream &operator<<(std::ostream &os, const connection_id &cid);

struct icmp_net_frame {
	const std::string buf;
	struct iphdr *ip;
	struct icmphdr *icmp;
	uint16_t device_id, orig_seq;
	std::string::const_iterator data_begin;
	std::shared_ptr<icmp_reply> reply;
	icmp_net_frame(const char *buf, int len);
	boost::asio::const_buffers_1 buffer() const;
	time_point_t inbound_deadline() const;
	time_point_t outbound_deadline() const;
	connection_id cid() const;
private:
	template<typename T>
	std::string::const_iterator read(std::string::const_iterator begin, T *&ptr);
};

typedef std::string tap_frame_t;
typedef icmp_net_frame raw_frame_t;
