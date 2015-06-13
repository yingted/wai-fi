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
#include <limits.h>
#include <boost/circular_buffer.hpp>

#include "tuntap.h"
#include "inet_checksum.h"

struct icmp_reply {
	__be32 addr;
	unsigned short id, seq;
	struct timespec time;
};

typedef __be32 connection_id;

struct connection {
	boost::circular_buffer<char>::size_type pos;
	set<icmp_reply> replies;
};

static bool lt_seq(const icmp_reply &a, const icmp_reply &b) {
	return a.seq < b.seq;
}

static bool operator<(const struct timespec &a, const struct timespec &b) {
	if (a.tv_sec != b.tv_sec) {
		return a.tv_sec < b.tv_sec;
	}
	return a.tv_nsec < b.tv_nsec;
}

static bool lt_time(const icmp_reply &a, const icmp_reply &b) {
	return a.time < b.time;
}

bool operator<(const icmp_reply &a, const icmp_reply &b) {
	return lt_seq(a, b);
}

int main(int argc, char *argv[]) {
	char dev[IFNAMSIZ + 1] = "icmp0";
	dev[IFNAMSIZ] = '\0';
	if (argc == 2) {
		strncpy(dev, argv[1], IFNAMSIZ);
	}
	char buf[64 * 1024]; // max IPv4 packet size
	int tap_fd, raw_fd, fd_max;
	boost::circular_buffer<char> outq(1024 * 1024);
	boost::circular_buffer<char>::size_type tot_recv = 0; // represents outq.end()
	fd_set fds;

	map<connection_id, connection> conns;

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

	{
		string cmd = "ip link set dev " + string(dev) + " up";
		system(cmd.c_str());
		cmd = "ifconfig " + string(dev) + " 192.168.10.1";
		system(cmd.c_str());
	}

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
			} else {
				if (len == sizeof(buf)) {
					printf("Warning: buffer full (%u bytes)\n", len);
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
						printf("received id=%d seq=%d saddr=%s\n", reply.id, reply.seq, inet_ntoa(*(in_addr *)&reply.addr));
						connection_id cid = reply.addr;
						bool new_conn = !conns.count(cid);
						connection &conn = conns[cid];
						if (new_conn) {
							printf("new connection to %s\n", inet_ntoa(*(in_addr *)&reply.addr));
							conn.pos = tot_recv;
						}
						conn.replies.insert(reply);

						if (data_len) {
							printf("tap: writing %d\n", data_len);
							ssize_t written = write(tap_fd, data, data_len);
							if (written < 0) {
								perror("write");
							} else if (written != data_len) {
								printf("wrote %d instead of %d\n", written, data_len);
							}
						}
					}
				}
			}
		}
		// Step 2: Collect data from the tap fd and update the outgoing queue.
		if (FD_ISSET(tap_fd, &fds)) {
			ssize_t len = read(tap_fd, buf, sizeof(buf));
			if (len < 0) {
				perror("recv tap");
			} else {
				printf("tap: reading %d\n", len);
				if (len == sizeof(buf)) {
					printf("Warning: buffer full (%u bytes)\n", len);
				}
				copy(buf, buf + len, back_inserter(outq));
				tot_recv += len;
			}
		}
		// Step 3: Write out the data to each connection.
		// Also time out some connections.
		// Split by:
		// getsockopt(raw_fd, SOL_SOCKET, SO_MAX_MSG_SIZE, (int *)&optval, &optlen);
		struct timespec min_time;
		clock_gettime(CLOCK_MONOTONIC, &min_time);
		min_time.tv_sec -= 30; // 30 seconds timeout
		for (auto &it : conns) {
			connection &conn = it.second;
			ssize_t to_write = tot_recv - conn.pos;
			ssize_t mtu = 1400 - 1; // for header
			int packets = (to_write + mtu - 1) / mtu;
			unsigned char queued = max<unsigned char>(0, min<unsigned long>(UCHAR_MAX, packets - conn.replies.size()));
			for (auto it = conn.replies.begin(); it != conn.replies.end(); conn.replies.erase(it++)) {
				if (conn.pos == tot_recv) {
					break; // queue is empty
				}
				const icmp_reply &reply = *it;
				printf("replying id=%d seq=%d saddr=%s\n", reply.id, reply.seq, inet_ntoa(*(in_addr *)&reply.addr));
				assert(conn.pos < tot_recv);
				ssize_t segsize = min<ssize_t>(mtu, tot_recv - conn.pos);
				assert(segsize <= to_write);

				char *out = buf;

				struct icmphdr *icmp = (struct icmphdr *)out;
				{
					out += sizeof(*icmp);
					icmp->type = ICMP_ECHOREPLY;
					icmp->code = 0;
					icmp->un.echo.id = htons(reply.id);
					icmp->un.echo.sequence = htons(reply.seq);
					icmp->checksum = 0;
				}

				*out++ = queued;

				out = copy(outq.end() - to_write, outq.end() - (to_write - segsize), out);
				to_write -= segsize;
				conn.pos += segsize;

				icmp->checksum = inet_checksum(icmp, out);

				struct sockaddr_in dst = {
					.sin_family = AF_INET,
					.sin_port = 0,
					.sin_addr = {
						.s_addr = reply.addr,
					},
				};
				ssize_t send_len = out - buf;
				assert(send_len <= sizeof(buf));
				ssize_t sent = sendto(raw_fd, buf, send_len, MSG_DONTWAIT, (struct sockaddr *)&dst, sizeof(dst));
				if (sent < 0) {
					perror("sendto");
				} else if (send_len != sent) {
					printf("sent %u instead of %u\n", sent, send_len);
				} else {
					printf("sent %u to %s\n", sent, inet_ntoa(*(in_addr *)&reply.addr));
				}
			}

			for (auto it = conn.replies.begin(); it != conn.replies.end();) {
				const icmp_reply &reply = *it;
				auto reply_it = it++;
				if (reply.time < min_time) {
					printf("timing out id=%d seq=%d saddr=%s\n", reply.id, reply.seq, inet_ntoa(*(in_addr *)&reply.addr));
					// XXX send empty reply?
					conn.replies.erase(reply_it);
				}
			}
		}
	}
}
