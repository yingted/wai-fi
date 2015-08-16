#include "types.h"
#include <iostream>
#include <boost/asio/spawn.hpp>
#include "icmp_net.h"
#include "icmp_reply.h"
#include "icmp_net_conn.h"
#include "icmp_net_conn_inbound.h"

using std::shared_ptr;
using std::make_shared;
using std::cout;
using std::endl;
namespace asio = boost::asio;
namespace chrono = std::chrono;
using asio::yield_context;

icmp_net_conn_inbound::icmp_net_conn_inbound(icmp_net_conn &conn, sequence_t next_i) :
	interruptible_loop(conn.icmp_net_.io_),
	conn_(conn),
	next_i_(next_i),
	last_frame_at_(boost_clock_t::now()) {
}

void icmp_net_conn_inbound::main_loop(yield_context yield) {
	for (;;) {

		// Find the next packet to process
		bool idle = false;
		inbound_t::iterator it;
		for (;;) {
			// Remove old packets (invalidates it)
			sliding_clear_half_below(next_i_);

			// Get a new timestamp
			time_point_t now = boost_clock_t::now();

			if (inbound_.empty()) {
				// Wait for any packet
				timer_.expires_at(last_frame_at_ + chrono::seconds(300));
				idle = true;
				cout << "inbound: wait for any packet" << endl;
				break;
			}
			// Check for sequentially next packet
			if ((it = inbound_.find(next_i_)) != inbound_.end()) {
				++next_i_;
				process_frame(it); // invalidates it
				continue;
			}
			// If we have any packets whose deadlines force us to process them, do so now
			{
				it = sliding_earlier_elements(next_i_, now,
					boost::bind(&icmp_net_conn_inbound::process_frame, this, _1)
				);
				if (it == inbound_.end()) {
					// Go to the empty case
					continue;
				}
				timer_.expires_at(it->second->inbound_deadline());
				cout << "inbound: wait for packet timeout" << endl;
				break;
			}
		}

		// Wait the timeout
		{
			// Either cancelled or a packet timed out
			if (!timer_wait()) {
				continue;
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
	cout << "inbound: closing connection " << conn_.cid_ << endl;
	conn_.stop();
}

void icmp_net_conn_inbound::process_frame(inbound_t::iterator it) {
	assert(it->second);
	cout << "process_frame: seq=" << it->first << endl;
	shared_ptr<raw_frame_t> frame(it->second);
	last_frame_at_ = it->second->reply->time;
	assert(it->second);
	conn_.icmp_net_.write_to_tap(*frame, *yield_);
	drop_frame(it);
}

icmp_net_conn_inbound::inbound_t::iterator icmp_net_conn_inbound::drop_frame(icmp_net_conn_inbound::inbound_t::iterator it) {
	icmp_reply &reply = *it->second->reply;
	cout << "drop_frame: seq=" << reply.orig_seq << endl;
	return inbound_.erase(it);
}

void icmp_net_conn_inbound::sliding_insert(shared_ptr<raw_frame_t> frame) {
	sequence_t seq = frame->orig_seq;
	inbound_.emplace(seq, frame);
	assert(inbound_[seq]);
	interrupt();
}

void icmp_net_conn_inbound::sliding_clear_half_below(sequence_t start) {
	static_assert(((sequence_t)-1) > 0, "sequence_t is signed");
	for (auto it = inbound_.begin(); it != inbound_.end();) {
		sequence_t diff = it->first - start;
		if (diff > std::numeric_limits<sequence_t>::max() / 2) {
			it = drop_frame(it);
		} else {
			++it;
		}
	}
}

// TODO improve the performance of this and the above function
icmp_net_conn_inbound::inbound_t::iterator icmp_net_conn_inbound::sliding_earlier_elements(sequence_t start, time_point_t now, boost::function<void(icmp_net_conn_inbound::inbound_t::iterator)> cb) {
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
