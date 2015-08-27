#include "types.h"
#include <boost/asio.hpp>
#include <boost/system/system_error.hpp>
#include <linux/if_tun.h>
#include <string>
#include <cstring>
#include <cerrno>
#include <boost/move/unique_ptr.hpp>
#include <boost/make_unique.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>
#include <iterator>
#include <stdexcept>
#include <sstream>
#include "tuntap.h"
#include "tap.h"

using namespace boost::system;
using namespace boost::iostreams;
using boost::asio::io_service;
using boost::asio::posix::stream_descriptor;
using std::string;

std::unique_ptr<stream_descriptor> create_tap_dev(io_service &io, const char *dev_arg) {
	char dev[IFNAMSIZ + 1];
	assert(dev_arg);
	strncpy(dev, dev_arg, IFNAMSIZ);

	int tap_fd;
	if ((tap_fd = tun_alloc(dev, IFF_TAP)) < 0) {
		throw system_error(errno, system_category(), "tun_alloc");
	}
	return boost::make_unique<stream_descriptor>(io, tap_fd);
}

static void check_call(const std::string &cmd) {
	if (int rc = std::system(cmd.c_str())) {
		std::stringstream err;
		err << "Command returned " << rc << ": " << cmd;
		throw std::runtime_error(err.str());
	}
}

static std::string check_output(const std::string &cmd) {
	FILE *fd = popen(cmd.c_str(), "r");
	std::string ret;
	int rc = 0;
	try {
		if (fd == NULL) {
			throw std::runtime_error("Could not run: " + cmd);
		}
		file_descriptor_source source(fileno(fd), never_close_handle);
		stream<file_descriptor_source> inp(source);
		ret = std::string(std::istreambuf_iterator<char>(inp), std::istreambuf_iterator<char>());
		rc = pclose(fd);
	} catch (std::runtime_error &exc) {
		rc = pclose(fd);
		throw;
	}
	if (rc) {
		std::stringstream err;
		err << "Command returned " << rc << ": " << cmd;
		throw std::runtime_error(err.str());
	}
	return ret;
}

void ip_set_up(const char *dev, int mtu) {
	printf("Opened tunnel on %s\n", dev);
	// Save some space for the mac header
	check_call("ip link set " + string(dev) + " mtu " + std::to_string(mtu - 16));
	check_call("ip link set dev " + string(dev) + " up");
	{
		string mac_addr = check_output("cat /sys/class/net/$(ip route list scope global | sed -n 's/^default .*\\<dev \\(\\S*\\)\\>.*/\\1/p' | head -1)/address");
		check_call("ifconfig " + string(dev) + " 192.168.10.1 hw ether " + mac_addr);
	}
}
