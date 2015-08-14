#define BOOST_ASIO_HAS_MOVE
#include <boost/asio.hpp>
#include <boost/system/system_error.hpp>
#include <utility>
#include <linux/if_tun.h>
#include <string>
#include <cstring>
#include <cerrno>

using namespace boost::system;
using boost::asio::io_service;
using boost::asio::posix::stream_descriptor;
using std::string;
using std::unique_ptr;

#include "tuntap.h"
#include "tap.h"

unique_ptr<stream_descriptor> create_tap_dev(io_service &io, const char *dev_arg) {
	char dev[IFNAMSIZ + 1];
	assert(dev_arg);
	strncpy(dev, dev_arg, IFNAMSIZ);

	int tap_fd;
	if ((tap_fd = tun_alloc(dev, IFF_TAP)) < 0) {
		throw system_error(errno, system_category(), "tun_alloc");
	}
	return unique_ptr<stream_descriptor>(new stream_descriptor(io, tap_fd));
}

void ip_set_up(const char *dev, int mtu) {
	printf("Opened tunnel on %.*s\n", IFNAMSIZ, dev);

	{
		string cmd;
		cmd = "ip link set " + string(dev) + " mtu " + std::to_string(mtu - 14); // mac header
		std::system(cmd.c_str());
		cmd = "ip link set dev " + string(dev) + " up";
		std::system(cmd.c_str());
		cmd = "ifconfig " + string(dev) + " 192.168.10.1";
		std::system(cmd.c_str());
	}
}
