#include "types.h"
#include <cstring>
#include "icmp_net.h"
#include "tap.h"
#include <boost/exception/get_error_info.hpp>

int main(int argc, char *argv[]) {
	char dev[IFNAMSIZ + 1] = "icmp0";
	dev[IFNAMSIZ] = '\0';
	if (argc == 2) {
		strncpy(dev, argv[1], IFNAMSIZ);
	}
	const ssize_t mtu = 1400 - 4; // for header

	try {
		icmp_net net(dev, mtu);
		net.run();
	} catch (const std::exception &e) {
		std::string const *stack(boost::get_error_info<boost::error_info<struct tag_stack_str, std::string> >(e));
		if (stack) {
			std::cerr << stack << std::endl;
		}
	}
}
