#pragma once

#include "icmp_reply.h"
#include <string>
#include <memory>
#include <boost/asio.hpp>

struct icmp_net_frame {
	const std::string buf;
	struct iphdr *ip;
	struct icmphdr *icmp;
	std::string::const_iterator data_begin;
	std::unique_ptr<icmp_reply> reply;
	icmp_net_frame(const char *buf, int len);
	boost::asio::const_buffers_1 buffer() const;
	time_point_t inbound_deadline() const;
	time_point_t outbound_deadline() const;
private:
	template<typename T>
	std::string::const_iterator read(std::string::const_iterator begin, T *&ptr);
};

typedef std::string tap_frame_t;
typedef icmp_net_frame raw_frame_t;
