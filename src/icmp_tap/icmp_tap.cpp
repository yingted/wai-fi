#include "types.h"
#include <cstring>
#include <boost/asio.hpp>
#include "icmp_net.h"

#include "tap.h"

int main(int argc, char *argv[]) {
	char dev[IFNAMSIZ + 1] = "icmp0";
	dev[IFNAMSIZ] = '\0';
	if (argc == 2) {
		strncpy(dev, argv[1], IFNAMSIZ);
	}
	const ssize_t mtu = 1400 - 2; // for header

	icmp_net net(dev, mtu);
	net.run();
}
