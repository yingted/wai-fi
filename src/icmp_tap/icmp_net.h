#pragma once

#include <string>
#include <boost/asio.hpp>
#include <boost/coroutine/all.hpp>

class icmp_net {
private:
	boost::asio::io_service io_;
	typedef std::string tap_frame_t;
	typedef std::string raw_frame_t;

	void tap_reader(boost::asio::yield_context yield);
	void raw_reader(boost::asio::yield_context yield);
public:
	icmp_net(const char *dev, int mtu);
};
