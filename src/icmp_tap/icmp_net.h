#pragma once

#include <string>
#include <boost/asio.hpp>
#include <boost/coroutine/all.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/signals2.hpp>
#include <boost/signals2/connection.hpp>
#include <boost/ptr_container/ptr_set.hpp>
#include <map>
#include "icmp_reply.h"
#include <linux/icmp.h>
#include <linux/ip.h>
#include "icmp_reply.h"
#include <memory>
#include <stdexcept>

class icmp_net_conn;

typedef unsigned short connection_id;

struct icmp_net_frame {
	const std::string buf;
	struct iphdr *ip;
	struct icmphdr *icmp;
	std::string::const_iterator data_begin;
	std::unique_ptr<icmp_reply> reply;
	icmp_net_frame(const char *buf, int len);
	boost::asio::const_buffers_1 buffer() const;
private:
	template<typename T>
	std::string::const_iterator read(std::string::const_iterator begin, T *&ptr);
};

class icmp_net {
public:
	typedef std::string tap_frame_t;
	typedef icmp_net_frame raw_frame_t;
	typedef boost::signals2::signal<void(const tap_frame_t &)> on_tap_frame_t;
	icmp_net(const char *dev, int mtu);
	void run();
	on_tap_frame_t on_tap_frame_;
private:
	boost::asio::io_service io_;
	boost::asio::posix::stream_descriptor tap_;
	boost::asio::ip::icmp::socket raw_;
	std::map<connection_id, std::shared_ptr<icmp_net_conn> > conns_;

	void tap_reader(boost::asio::yield_context yield);
	void raw_reader(boost::asio::yield_context yield);
};

class icmp_net_conn {
	icmp_net *const icmp_net_;
	boost::ptr_set<icmp_reply> replies_;
	struct timespec time_;
	boost::signals2::scoped_connection sig_conn_;
public:
	icmp_net_conn(icmp_net &inet, const std::unique_ptr<icmp_reply> &first);
	void on_tap_frame(const icmp_net::tap_frame_t &frame);
	void on_icmp_echo(std::unique_ptr<icmp_reply> &icmp_reply);
};
