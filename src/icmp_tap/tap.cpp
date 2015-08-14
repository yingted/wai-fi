#include <boost/asio.hpp>
#include <boost/system/system_error.hpp>
#include <utility>
#include <linux/if_tun.h>
#include <string>

using namespace boost::system;
using boost::asio::io_service;
using boost::asio::posix::stream_descriptor;
using std::string;

#include "tuntap.h"

stream_descriptor &&create_tap_dev(io_service &io, char *dev) {
	int tap_fd;
	if ((tap_fd = tun_alloc(dev, IFF_TAP)) < 0) {
		throw system_error(errno, system_category(), "tun_alloc");
	}
	return std::move(stream_descriptor(io, tap_fd));
}

void ip_set_up(char *dev, int mtu) {
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
