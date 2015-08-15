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
#include "icmp_net_frame.h"
#include "icmp_net_conn.h"
#include "interruptible_loop.h"

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

icmp_net_conn::icmp_net_conn(icmp_net &inet, connection_id cid, sequence_t first) :
	icmp_net_(&inet),
	sig_conn_(inet.on_tap_frame_.connect(boost::bind(&icmp_net_conn::on_tap_frame, this, _1))),
	inbound_timer_(inet.io_),
	outbound_timer_(inet.io_),
	cid_(cid),
	next_i_(first),
	echo_yield_(NULL),
	tap_yield_(NULL),
	queued_(0),
	alive_(true) {
	asio::spawn(inet.io_, boost::bind(&icmp_net_conn::echo_writer, this, _1));
	asio::spawn(inet.io_, boost::bind(&icmp_net_conn::echo_reader, this, _1));
}

void icmp_net_conn::stop() {
	alive = false;
	inbound_timer_.cancel();
	outbound_timer_.cancel();
	// Let's extend its life a bit
	auto sp = icmp_net_->conns_[cid_];
	icmp_net_->conns_.erase(cid_);
	assert(sp.use_count() == 1);
}

void icmp_net_conn::echo_writer(yield_context yield) {
	assert(tap_yield_ == NULL);
	tap_yield_ = &yield;
	XXX
	assert(tap_yield_);
	tap_yield_ = NULL;
	stop();
}

void icmp_net_conn::echo_reader(yield_context yield) {
	assert(echo_yield_ == NULL);
	echo_yield_ = &yield;
	for (;;) {

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
				inbound_timer_.expires_at(now + chrono::seconds(300));
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
				inbound_timer_.expires_at(it->second->inbound_deadline());
				cout << "echo_reader: wait for packet timeout" << endl;
				break;
			}
		}

		// Wait the timeout
		{
			// Either cancelled or a packet timed out
			{
				boost::system::error_code ec;
				inbound_timer_.async_wait(yield[ec]);
				if (!alive_) {
					break;
				}
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
	assert(echo_yield_);
	echo_yield_ = NULL;
	stop();
}

void icmp_net_conn::send_outbound_reply(icmp_reply &reply) {
	assert(!reply.consumed);
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
	reply.consumed = true;

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
	icmp_reply &reply = *it->second->reply;
	if (!reply.consumed) {
		send_outbound_reply(reply);
	}
	cout << "drop_inbound_frame: seq=" << reply.seq << endl;
	return inbound_.erase(it);
}

void icmp_net_conn::on_tap_frame(shared_ptr<const icmp_net::tap_frame_t> frame) {
	cout << "on_tap_frame: read: " << frame->size() << " B" << endl;
	outbound_.push_back(frame);
	outbound_timer_.cancel();
}

void icmp_net_conn::on_raw_frame(unique_ptr<icmp_net::raw_frame_t> &frame) {
	cout << "on_raw_frame: echo: seq=" << frame->reply->seq << endl;
	inbound_sliding_insert(frame);
	outbound_insert(frame);
	inbound_timer_.cancel();
	outbound_timer_.cancel();
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

