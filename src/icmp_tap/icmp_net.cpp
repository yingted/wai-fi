#define BOOST_ASIO_HAS_MOVE
#include <algorithm>
#include <map>
#include <set>
#include <utility>
#include <functional>
#include <iostream>
#include <stdexcept>
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
#include "tap.h"
#include "inet_checksum.h"
#include "icmp_net.h"
#include "icmp_reply.h"

using std::string;
using std::unique_ptr;
using std::shared_ptr;
using std::make_shared;
using std::invalid_argument;
using std::cout;
using std::endl;
namespace asio = boost::asio;
namespace chrono = std::chrono;
using boost::make_unique;
using asio::yield_context;
using asio::ip::icmp;
using asio::io_service;
using boost::signals2::scoped_connection;

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
			on_tap_frame_(std::const_pointer_cast<const tap_frame_t>(shared_frame));
		}
	}
}

icmp_net_conn::icmp_net_conn(icmp_net &inet, connection_id cid, sequence_t first) :
	icmp_net_(&inet),
	sig_conn_(inet.on_tap_frame_.connect(boost::bind(&icmp_net_conn::on_tap_frame, this, _1))),
	timer_(inet.io_),
	cid_(cid),
	next_i_(first),
	yield_(NULL),
	queued_(0) {
	asio::spawn(inet.io_, boost::bind(&icmp_net_conn::echo_reader, this, _1));
}

void icmp_net::write_to_tap(const icmp_net::raw_frame_t &frame, yield_context yield) {
	ssize_t data_len = asio::buffer_size(frame.buffer());
	if (data_len) {
		ssize_t written = tap_.async_write_some(frame.buffer(), yield);
		cout << "raw_reader: tap: write: " << written << " of " << data_len << " B" << endl;
		if (written != data_len) {
			cout << "raw_reader: tap: write: wrong number of bytes written" << endl;
		}
	} else {
		cout << "got keepalive" << endl;
	}
}

time_point_t icmp_net_frame::inbound_deadline() const {
	return reply->time + chrono::milliseconds(500);
}

void icmp_net_conn::echo_reader(yield_context yield) {
	assert(yield_ == NULL);
	yield_ = &yield;
	for (;;) {
		process_outbound_frames();

		// Find the next packet to process
		bool idle = false;
		inbound_t::iterator it;
		for (;;) {
			// Remove old packets (invalidates it)
			inbound_sliding_clear_half_below(next_i_);

			// Get a new timestamp
			time_point_t now = chrono::steady_clock::now();

			if (inbound_.empty()) {
				// Wait for any packet
				timer_.expires_at(now + chrono::seconds(150));
				idle = true;
				cout << "echo_reader: wait for any packet" << endl;
				break;
			}
			// Check for sequentially next packet
			if ((it = inbound_.find(next_i_)) != inbound_.end()) {
				++next_i_;
				process_inbound_frame(it); // invalidates it
				continue;
			}
			// If we have any packets whose deadlines force us to process them, do so now
			{
				it = inbound_sliding_earlier_elements(next_i_, now,
					boost::bind(&icmp_net_conn::process_inbound_frame, this, _1)
				);
				if (it == inbound_.end()) {
					// Go to the empty case
					continue;
				}
				timer_.expires_at(it->second->inbound_deadline());
				cout << "echo_reader: wait for packet timeout" << endl;
				break;
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
	cout << "echo_reader: closing connection " << cid_ << endl;
	icmp_net_->conns_.erase(cid_);
	assert(yield_);
	yield_ = NULL;
}

void icmp_net_conn::send_outbound_reply(const icmp_reply &reply) {
	reply.consumed = true;
	shared_ptr<const icmp_net::tap_frame_t> frame;
	{
		auto it = outbound_.begin();
		if (it == outbound_.end()) {
			return;
		}
		frame = *it;
		outbound_.erase(it);
	}

	printf("replying id=%d seq=%d saddr=%s\n", reply.id, reply.seq, inet_ntoa(*(in_addr *)&reply.addr));

	// XXX This depends on not doing IO between this and async_send_to
	static char buf[64 * 1024];
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

	*out++ = queued_;
	// padding
	*out++ = 0;

	out = std::copy(frame->begin(), frame->end(), out);

	icmp->checksum = inet_checksum(icmp, out);

	icmp_net::raw_t::endpoint_type dst(asio::ip::address::from_string(inet_ntoa(*(in_addr *)&reply.addr)), reply.id);
	ssize_t send_len = out - buf;
	assert(((size_t)send_len) <= sizeof(buf));

	icmp_net_->write_to_raw(asio::buffer((const char *)buf, send_len), dst, *yield_);
}

void icmp_net::write_to_raw(asio::const_buffers_1 buf, icmp_net::raw_t::endpoint_type dst, yield_context yield) {
	ssize_t send_len = asio::buffer_size(buf);
	ssize_t sent = raw_.async_send_to(buf, dst, MSG_DONTWAIT, yield);
	if (send_len != sent) {
		cout << "sent " << sent << " instead of " << send_len << endl;
	} else {
		cout << "sent " << sent << " to " << dst << endl;
	}
}

void icmp_net_conn::process_outbound_frames() {
	std::vector<icmp_reply *> replies;
	// TODO improve the performance of all the sliding window stuff
	for (const auto &it : inbound_) {
		icmp_reply *reply = it.second->reply.get();
		if (!reply->consumed) {
			replies.push_back(reply);
		}
	}
	std::sort(replies.begin(), replies.end(), [](icmp_reply *a, icmp_reply *b) {
		return a->time < b->time;
	});
	queued_ = std::max<long>(0, std::min<long>(UCHAR_MAX, (long)outbound_.size() - (long)replies.size()));
	for (const auto &reply : replies) {
		if (outbound_.empty()) {
			break;
		}
		send_outbound_reply(*reply);
	}
}

void icmp_net_conn::process_inbound_frame(inbound_t::iterator it) {
	assert(it->second);
	unique_ptr<icmp_net::raw_frame_t> &frame(it->second);
	assert(it->second);
	icmp_net_->write_to_tap(*frame, *yield_);
	drop_inbound_frame(it);
}

icmp_net_conn::inbound_t::iterator icmp_net_conn::drop_inbound_frame(inbound_t::iterator it) {
	send_outbound_reply(*it->second->reply);
	cout << "drop_inbound_frame: seq=" << it->second->reply->seq << endl;
	return inbound_.erase(it);
}

void icmp_net_conn::on_tap_frame(shared_ptr<const icmp_net::tap_frame_t> frame) {
	cout << "on_tap_frame: read: " << frame->size() << " B" << endl;
	outbound_.push_back(frame);
	notify();
}

void icmp_net_conn::on_raw_frame(unique_ptr<icmp_net::raw_frame_t> &frame) {
	cout << "on_raw_frame: echo: seq=" << frame->reply->seq << endl;
	inbound_sliding_insert(frame);
	notify();
}

void icmp_net_conn::inbound_sliding_insert(unique_ptr<icmp_net::raw_frame_t> &frame) {
	sequence_t seq = frame->reply->seq;
	inbound_.emplace(seq, std::move(frame));
	assert(inbound_[seq]);
}

void icmp_net_conn::inbound_sliding_clear_half_below(sequence_t start) {
	static_assert(((sequence_t)-1) > 0, "sequence_t is signed");
	for (auto it = inbound_.begin(); it != inbound_.end();) {
		sequence_t diff = it->first - start;
		if (diff > std::numeric_limits<sequence_t>::max() / 2) {
			it = drop_inbound_frame(it);
		} else {
			++it;
		}
	}
}

// TODO improve the performance of this and the above function
icmp_net_conn::inbound_t::iterator icmp_net_conn::inbound_sliding_earlier_elements(sequence_t start, time_point_t now, boost::function<void(icmp_net_conn::inbound_t::iterator)> cb) {
	inbound_t::iterator lb_start = inbound_.lower_bound(start), it;
	assert(!inbound_.empty());

	auto max_until_now = inbound_.end();
	it = lb_start;
	for (size_t count = inbound_.size(); (it = (it == inbound_.end() ? inbound_.begin() : it)), count--;) {
		if (it->second->inbound_deadline() <= now) {
			if (max_until_now == inbound_.end() || max_until_now->first >= it->first) {
				max_until_now = it;
			}
		}
		++it;
	}
	// No items to output. Everything is after deadline.
	if (max_until_now == inbound_.end()) {
		// Inline the first iteration of the loop
		it = lb_start == inbound_.end() ? inbound_.begin() : lb_start;
		// Check we're returning something
		assert(it != inbound_.end());
		return it;
	}

	it = lb_start;
	// From here, we might invalidate iterators
	for (size_t count = inbound_.size(); (it = (it == inbound_.end() ? inbound_.begin() : it)), count--;) {
		assert(it != inbound_.end());
		auto saved_it = it;
		if (it++ == max_until_now) {
			// Advance the iterator and break
			count = 0;
		}
		cb(saved_it);
	}
	assert((it != inbound_.end()) == !!inbound_.empty());
	return it;
}

void icmp_net_conn::notify() {
	timer_.cancel();
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
	printf("icmp_net_frame: id=%d seq=%d saddr=%s\n", reply->id, reply->seq, inet_ntoa(*(in_addr *)&reply->addr));
}

void icmp_net::run() {
	io_.run();
}
