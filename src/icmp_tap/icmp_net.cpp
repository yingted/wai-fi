#define BOOST_ASIO_HAS_MOVE
#include <algorithm>
#include <map>
#include <set>
#include <utility>
#include <functional>
#include <iostream>
#include <stdexcept>

using namespace std;

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
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

		{
			shared_ptr<tap_frame_t> shared_frame(std::move(frame));
			on_tap_frame_(const_pointer_cast<const tap_frame_t>(shared_frame));
		}
	}
}

icmp_net_conn::icmp_net_conn(icmp_net &inet, connection_id cid, sequence_t first) :
	icmp_net_(&inet),
	sig_conn_(inet.on_tap_frame_.connect(boost::bind(&icmp_net_conn::on_tap_frame, this, _1))),
	timer_(inet.io_),
	cid_(cid),
	next_i_(first) {
	asio::spawn(inet.io_, boost::bind(&icmp_net_conn::echo_reader, this, _1));
}

void icmp_net::write_to_tap(const icmp_net::raw_frame_t &frame) {
	ssize_t data_len = asio::buffer_size(frame->buffer());
	if (data_len) {
		ssize_t written = tap_.async_write_some(frame->buffer(), yield);
		cout << "raw_reader: tap: write: " << written << " of " << data_len << " B" << endl;
		if (written != data_len) {
			cout << "raw_reader: tap: write: wrong number of bytes written" << endl;
		}
	}
}

void icmp_net_conn::echo_reader(yield_context yield) {
	for (;;) {
		// Find the next packet to process
		chrono::time_point now = chrono::steady_clock::now();
		bool idle = false;
		auto it;
		for (;;) {
			if (inbound_.empty()) {
				// Wait for any packet
				timer_.expires_at(now + chrono::seconds(150));
				idle = true;
				break;
			}
			// Remove old packets
			inbound_sliding_clear_half_below(next_i_);
			// Check for sequentially next packet
			if ((it = inbound_.find(next_i_)) != inbound_.end()) {
				std::unique_ptr<icmp_net_frame> frame(move(it->second));
				++next_i_;
				inbound_.erase(it);
				process_inbound_frame(frame);
				continue;
			}
			// If we have any packets whose deadlines force us to process them, do so now
			{
				it = inbound_sliding_earlier_elements(next_i_, now, boost::bind(&icmp_net_conn::process_inbound_frame, this, _1));
				assert(it != inbound_.end());
				timer_.expires_at(it->inbound_deadline());
			}
		}

		// Wait the timeout
		{
			// Either cancelled or a packet timed out
			{
				boost::system::error_code ec;
				timer_.async_wait(yield[ec]);
				if (ec) { // Cancelled, refresh everything
					assert(ec == boost::asio::error::operation_aborted);
					continue;
				}
			}

			// Connection died
			if (idle) {
				break;
			}
		}
		// Seek to next position
		next_i_ = it->first;
	}
	// Clean-up
	cout << "Closing connection " << cid_ << endl;
	icmp_net_->conns_.erase(cid_);
}

void icmp_net_conn::process_inbound_frame(unique_ptr<icmp_net::raw_frame_t> &frame) {
	icmp_net_->write_to_tap(*frame);
}

void icmp_net_conn::on_tap_frame(shared_ptr<const icmp_net::tap_frame_t> frame) {
	cout << "on_tap_frame: read: " << frame->size() << " B" << endl;
	outbound_.push(frame);
	notify();
}

void icmp_net_conn::on_raw_frame(unique_ptr<icmp_net::raw_frame_t> &frame) {
	cout << "on_raw_frame: echo: " << frame->reply->seq << endl;
	inbound_sliding_insert(frame);
	notify();
}

void icmp_net_conn::inbound_sliding_insert(unique_ptr<icmp_net::raw_frame_t> &frame) {
	inbound_.insert(std::move(frame));
}

void icmp_net_conn::inbound_sliding_clear_half_below(sequence_t start) {
	static_assert(((sequence_t)-1) > 0);
	for (auto it = inbound_.begin(); it != inbound_.end();) {
		if ((sequence_t)(it->first - start) <= numeric_limits<sequence_t>::max() / 2) {
			it = inbound_.erase(it);
		} else {
			++it;
		}
	}
}

// TODO improve the performance
icmp_net_conn::inbound_t::iterator icmp_net_conn::inbound_sliding_earlier_element(sequence_t start, chrono::time_point now, function<void(icmp_net_conn::inbound_t::iterator)> cb) {
	auto begin0 = inbound_.lower_bound(start), end0 = inbound_.end(), begin1 = inbound_.begin(), it;

	auto max_until_now = inbound_.end();
	it = begin0;
	for (size_t count = inbound_.size(); (it == end0 && (it = begin1)), count--;) {
		if (it->second->inbound_deadline() <= now) {
			if (max_until_now == inbound_.end() || max_until_now->first >= it->first) {
				max_until_now = it;
			}
		}
		++it;
	}
	// No items to output
	if (max_until_now == inbound_.end()) {
		return inbound_.end();
	}

	it = begin0;
	for (size_t count = inbound_.size(); (it == end0 && (it = begin1)), count--;) {
		cb(it);
		if (it == max_until_now) {
			// Advance the iterator and break
			count = 0;
		}
		++it;
	}
	return it;
}

void icmp_net_conn::notify() {
	size_t count = timer_.cancel();
	assert(count == 1);
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
			cout << "raw_reader: make_unique<raw_frame_t>: " << exc.what() << endl;
			continue;
		}

		{
			assert(frame->reply);
			connection_id cid = frame->reply->id;
			bool new_conn = !conns_.count(cid);
			if (new_conn) {
				printf("raw_reader: new connection to %s\n", inet_ntoa(*(in_addr *)&frame->reply->addr));
				conns_.emplace(cid, make_shared<icmp_net_conn>(*this, cid, frame->reply->seq));
			}
			conns_[cid]->on_raw_frame(frame);
			assert(!frame);
		}
	}
}

asio::const_buffers_1 icmp_net_frame::buffer() const {
	return asio::buffer(data_begin - buf.begin() + buf.data(), buf.end() - data_begin);
}

template<typename T>
string::const_iterator icmp_net_frame::read(string::const_iterator begin, T *&ptr) {
	if (buf.end() - begin < sizeof(*ptr)) {
		throw invalid_argument("packet too short");
	}
	ptr = (T *)(begin - buf.begin() + buf.data());
	return begin + sizeof(*ptr);
}

icmp_net_frame::icmp_net_frame(const char *buf_arg, int len) :
	buf(buf_arg, len) {
	// Skip headers
	if (len == sizeof(buf)) {
		cout << "Warning: buffer full (" << len << " bytes)" << endl;
	}
	string::const_iterator begin = buf.begin();
	read(begin, ip);
	data_begin = read(begin + ip->ihl * 4, icmp);

	// Verify some fields
	unsigned short tot_len = ntohs(ip->tot_len);
	if (len != tot_len) {
		printf("Expected tot_len=%d, got tot_len=%d\n", len, tot_len);
		throw invalid_argument("invalid packet length");
	}
	if (icmp->type != ICMP_ECHO) {
		throw invalid_argument("unexpected ICMP packet type");
	}

	reply = make_unique<icmp_reply>(ip->saddr, ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
	printf("received id=%d seq=%d saddr=%s\n", reply->id, reply->seq, inet_ntoa(*(in_addr *)&reply->addr));
}

#if 0
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
#endif

void icmp_net::run() {
	io_.run();
}
