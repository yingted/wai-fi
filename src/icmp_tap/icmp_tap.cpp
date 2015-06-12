#include <algorithm>
#include <map>
#include <set>

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
#include <linux/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>

#include "tuntap.h"

struct icmp_reply {
	__be32 addr;
	unsigned short id, seq;
	struct timespec time;
};

static bool lt_seq(const icmp_reply &a, const icmp_reply &b) {
	return a.seq < b.seq;
}

static bool lt_time(const icmp_reply &a, const icmp_reply &b) {
	if (a.time.tv_sec != b.time.tv_sec) {
		return a.time.tv_sec < b.time.tv_sec;
	}
	return a.time.tv_nsec < b.time.tv_nsec;
}

bool operator<(const icmp_reply &a, const icmp_reply &b) {
	return lt_seq(a, b);
}

int main(int argc, char *argv[]) {
	char dev[IFNAMSIZ] = "icmp0";
	char buf[64 * 1024]; // max IPv4 packet size
	int tap_fd, raw_fd, fd_max;
	fd_set fds;

	map<__be32, set<icmp_reply> > replies;

	if ((tap_fd = tun_alloc(dev, IFF_TAP)) < 0) {
		perror("tun_alloc");
		return -1;
	}

	{
		int flags = fcntl(tap_fd, F_GETFL, 0);
		if (fcntl(tap_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			perror("fcntl: nonblock");
		}
	}

	if ((raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		perror("socket");
		return -1;
	}

	struct icmp_filter filt;
	filt.data = ~(1U << ICMP_ECHO);
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
			struct iphdr *ip = (struct iphdr *)buf;
			ssize_t len = recv(raw_fd, buf, sizeof(buf), MSG_DONTWAIT);
			if (len < 0) {
				perror("recv ip");
				return -1;
			}
			ssize_t ip_hlen = ip->ihl * 4;
			struct icmphdr *icmp = (struct icmphdr *)(((char *)ip) + ip_hlen);
			unsigned short tot_len = ntohs(ip->tot_len);
			if (len != tot_len) {
				printf("Expected tot_len=%d, got tot_len=%d\n", len, tot_len);
			} else {
				char *data = ((char *)icmp) + sizeof(*icmp);
				ssize_t data_len = buf + len - data;

				if (icmp->type == ICMP_ECHO) {
					icmp_reply reply;
					reply.id = ntohs(icmp->un.echo.id);
					reply.seq = ntohs(icmp->un.echo.sequence);
					reply.addr = ip->saddr;
					clock_gettime(CLOCK_MONOTONIC, &reply.time);
					printf("id=%d seq=%d saddr=%u\n", reply.id, reply.seq, reply.addr);
					replies[reply.addr].insert(reply);

					ssize_t written = write(tap_fd, data, data_len);
					if (written < 0) {
						perror("write");
					} else if (written != data_len) {
						printf("wrote %d instead of %d\n", written, data_len);
					}
				}
			}
		}
		// Step 2: Collect data from the tap fd and update the outgoing queues.
		if (FD_ISSET(tap_fd, &fds)) {
			//l = read(tap_fd, buf, sizeof(buf));
		}
		// Step 3: Write out the data to each connection.
		// Also time out some connections.
		// Split via:
		// getsockopt(socket, SOL_SOCKET, SO_MAX_MSG_SIZE, (int *)&optval, &optlen);
	}
}
