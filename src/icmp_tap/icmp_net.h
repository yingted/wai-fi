#pragma once

#include <string>
#include <boost/asio.hpp>
#include <boost/coroutine/all.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/signals2.hpp>
#include <boost/signals2/connection.hpp>
#include <map>
#include "icmp_reply.h"

class icmp_net_conn;

typedef unsigned short connection_id;

class icmp_net {
public:
	typedef std::string tap_frame_t;
	typedef std::string raw_frame_t;
	typedef boost::signals2::signal<void(const tap_frame_t &)> on_tap_frame_t;
	icmp_net(const char *dev, int mtu);
	void run();
private:
	boost::asio::io_service io_;
	boost::asio::posix::stream_descriptor tap_;
	boost::asio::ip::icmp::socket raw_;
	on_tap_frame_t on_tap_frame_;
	std::map<connection_id, icmp_net_conn> conns_;

	void tap_reader(boost::asio::yield_context yield);
	void raw_reader(boost::asio::yield_context yield);
};

class icmp_net_conn {
	size_t pos_;
	std::set<icmp_reply> replies_;
	struct timespec time_;
	boost::signals2::scoped_connection sig_conn_;
public:
	icmp_net_conn(icmp_net::on_tap_frame_t &sig);
	void on_tap_frame(icmp_net::tap_frame_t frame);
};
