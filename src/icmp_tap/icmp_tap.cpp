#include <algorithm>
#include <vector>

using namespace std;

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <stdlib.h>

#include "tuntap.h"
#include "icmp_tap_tx.h"

int main(int argc, char *argv[]) {
	char dev[IFNAMSIZ] = "icmp0";
	char buf[1500];
	int tap_fd, raw_fd, fd_max;
	fd_set fds;

	if ((tap_fd = tun_alloc(dev, IFF_TAP)) < 0) {
		perror("tun_alloc");
		return -1;
	}

	if ((raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		perror("socket");
		return -1;
	}

	struct icmp_filter filt;
	filt.data = ~(1U << 0U);
	if (setsockopt(raw_fd, IPPROTO_RAW, ICMP_FILTER, &filt, sizeof(filt)) < 0) {
		perror("setsockopt");
	}

	fd_max = max(tap_fd, raw_fd) + 1;

	printf("Opened tunnel on %.*s\n", IFNAMSIZ, dev);

	for (;;) {
		FD_ZERO(&fds);
		FD_SET(tap_fd, &fds);
		FD_SET(raw_fd, &fds);

		select(fd_max, &fds, NULL, NULL, NULL);

		// Step 1: Collect echo requests and write out data to the tap fd.
		// Subscribe any active connections to the stream.
		// Assume that writing to tap is non-blocking.
		if (FD_ISSET(raw_fd, &fds)) {
			l = read(raw_fd, buf, sizeof(buf));
		}
		// Step 2: Collect data from the tap fd and update the outgoing queues.
		if (FD_ISSET(tap_fd, &fds)) {
			l = read(tap_fd, buf, sizeof(buf));
		}
		// Step 3: Write out the data to each connection.
		// Also time out some connections.
		// Split via:
		// getsockopt(socket, SOL_SOCKET, SO_MAX_MSG_SIZE, (int *)&optval, &optlen);
	}
}
