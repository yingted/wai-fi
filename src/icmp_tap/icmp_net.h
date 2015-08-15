#pragma once

#include "types.h"
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/signals2.hpp>
#include <map>
#include <memory>
#include "icmp_net_frame.h"

class icmp_net_conn;

class icmp_net {
public:
	typedef boost::asio::posix::stream_descriptor tap_t;
	typedef boost::asio::ip::icmp::socket raw_t;
	typedef boost::signals2::signal<void(std::shared_ptr<const tap_frame_t>)> on_tap_frame_t;
	icmp_net(const char *dev, int mtu);
	void run();
	void write_to_tap(const raw_frame_t &frame, boost::asio::yield_context yield);
	void write_to_raw(boost::asio::const_buffers_1 buf, raw_t::endpoint_type, boost::asio::yield_context yield);
	on_tap_frame_t on_tap_frame_;
	boost::asio::io_service io_;
	std::map<connection_id, std::shared_ptr<icmp_net_conn> > conns_;
private:
	tap_t tap_;
	raw_t raw_;

	void tap_reader(boost::asio::yield_context yield);
	void raw_reader(boost::asio::yield_context yield);
};
