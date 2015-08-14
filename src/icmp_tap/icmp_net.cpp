#define BOOST_ASIO_HAS_MOVE
#include <algorithm>
#include <map>
#include <set>
#include <utility>
#include <functional>
#include <iostream>

using namespace std;

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <boost/circular_buffer.hpp>
#include <boost/asio.hpp>
#include <boost/coroutine/all.hpp>
#include <boost/signals2/connection.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/make_unique.hpp>

namespace asio = boost::asio;
using boost::make_unique;
using asio::yield_context;
using asio::ip::icmp;
using asio::io_service;
using boost::signals2::scoped_connection;

#include "tap.h"
#include "inet_checksum.h"
#include "icmp_net.h"
#include "icmp_reply.h"

icmp_net::icmp_net(const char *dev, int mtu) :
	io_(),
	tap_(std::move(*create_tap_dev(io_, dev))),
	raw_(io_, icmp::v4()) {
	tap_.native_non_blocking(true);

	{
		struct icmp_filter filt;
		filt.data = ~(1U << ICMP_ECHO);
		if (setsockopt(raw_.native(), IPPROTO_RAW, ICMP_FILTER, &filt, sizeof(filt)) < 0) {
			perror("setsockopt");
		}
	}

	ip_set_up(dev, mtu);

	asio::spawn(io_, boost::bind(&icmp_net::tap_reader, this, _1));
	asio::spawn(io_, boost::bind(&icmp_net::raw_reader, this, _1));
}

void icmp_net::tap_reader(yield_context yield) {
	cout << "tap_reader: started" << endl;
	for (;;) {
		static char buf[64 * 1024];
		ssize_t len = tap_.async_read_some(asio::buffer(buf), yield);
		cout << "tap_reader: read: " << len << " B" << endl;
		unique_ptr<tap_frame_t> frame;
		try {
			frame = make_unique<tap_frame_t>(buf, len);
		} catch (const invalid_argument &exc) {
			cout << "make_unique<tap_frame_t>: " << exc.what() << endl;
			continue;
		}
		on_tap_frame_(*frame);
	}
}

icmp_net_conn::icmp_net_conn(icmp_net::on_tap_frame_t &sig) :
	sig_conn_(sig.connect(boost::bind(&icmp_net_conn::on_tap_frame, this, _1))) {
}

void icmp_net_conn::on_tap_frame(icmp_net::tap_frame_t frame) {
	cout << "on_tap_frame: read: " << frame.size() << " B" << endl;
	// XXX
}

void icmp_net::raw_reader(yield_context yield) {
	cout << "raw_reader: started" << endl;
	for (;;) {
		static char buf[64 * 1024];
		ssize_t len = raw_.async_receive(asio::buffer(buf), yield);
		cout << "raw_reader: read: " << len << " B" << endl;

		unique_ptr<raw_frame_t> frame;
		try {
			frame = make_unique<raw_frame_t>(buf, len);
		} catch (const invalid_argument &exc) {
			cout << "make_unique<raw_frame_t>: " << exc.what() << endl;
			continue;
		}

#if 0
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
						icmp_reply reply(ip->saddr, icmp->un.echo.id, icmp->un.echo.sequence);
						printf("received id=%d seq=%d saddr=%s\n", reply.id, reply.seq, inet_ntoa(*(in_addr *)&reply.addr));
						connection_id cid = reply.id;
						bool new_conn = !conns.count(cid);
						icmp_net_conn &conn = conns[cid];
						if (new_conn) {
							printf("new connection to %s\n", inet_ntoa(*(in_addr *)&reply.addr));
							conn.pos = tot_recv;
						}
						conn.time = reply.time;
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
#endif
	}
}

#if 0
	boost::circular_buffer<frame_t> outq(1024);
	size_t tot_recv = 0; // represents outq.end()
	fd_set fds;
	map<connection_id, icmp_net_conn> conns;
	char buf[64 * 1024]; // max IPv4 packet size

	for (;;) {
		// Step 3: Write out the data to each connection.
		// Also time out some connections.
		// Split by:
		// getsockopt(raw_fd, SOL_SOCKET, SO_MAX_MSG_SIZE, (int *)&optval, &optlen);
		struct timespec min_time;
		clock_gettime(CLOCK_MONOTONIC, &min_time);
		min_time.tv_sec -= 150; // 150 seconds timeout
		for (auto &it : conns) {
			icmp_net_conn &conn = it.second;
			size_t packets = tot_recv - conn.pos;
			unsigned char queued = max<unsigned char>(0, min<long>(UCHAR_MAX, (long)packets - (long)conn.replies.size()));
			for (auto it = conn.replies.begin(); it != conn.replies.end(); conn.replies.erase(it++)) {
				if (conn.pos == tot_recv) {
					break; // queue is empty
				}
				const icmp_reply &reply = *it;
				printf("replying id=%d seq=%d saddr=%s\n", reply.id, reply.seq, inet_ntoa(*(in_addr *)&reply.addr));
				assert(conn.pos < tot_recv);

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
				// padding
				*out++ = 0;

				const string &frame = *(outq.end() - (tot_recv - conn.pos++));
				out = copy(frame.begin(), frame.end(), out);

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
		for (auto it = conns.begin(); it != conns.end();) {
			if (it->second.time < min_time) {
				printf("closing connection\n");
				conns.erase(it++);
			} else {
				++it;
			}
		}
	}
#endif

void icmp_net::run() {
	io_.run();
}
