#pragma once

#include <string>
#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/coroutine/all.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/signals2.hpp>
#include <boost/signals2/connection.hpp>
#include "types.h"
#include <map>
#include <deque>
#include "icmp_reply.h"
#include <linux/icmp.h>
#include <linux/ip.h>
#include <memory>
#include <stdexcept>
#include "icmp_net.h"

class icmp_net_conn {
public:
	typedef unsigned short sequence_t; // must be unsigned
	icmp_net_conn(icmp_net &inet, connection_id cid, sequence_t first);
	void on_tap_frame(std::shared_ptr<const icmp_net::tap_frame_t> frame);
	void on_raw_frame(std::unique_ptr<icmp_net::raw_frame_t> &frame);
	typedef std::map<sequence_t, std::unique_ptr<icmp_net_frame> > inbound_t;
	typedef std::deque<std::shared_ptr<const icmp_net::tap_frame_t> > outbound_t;
private:
	icmp_net *const icmp_net_;
	outbound_t outbound_;
	inbound_t inbound_;
	boost::signals2::scoped_connection sig_conn_;
	boost_timer_t inbound_timer_, outbound_timer_;
	connection_id cid_;
	sequence_t next_i_;
	boost::asio::yield_context *echo_yield_, *tap_yield_;
	unsigned char queued_;

	void inbound_sliding_insert(std::unique_ptr<icmp_net::raw_frame_t> &frame);
	void inbound_sliding_clear_half_below(sequence_t start);
	inbound_t::iterator inbound_sliding_earlier_elements(sequence_t start, time_point_t now, boost::function<void(inbound_t::iterator)> cb);
	void stop();
	void echo_writer(boost::asio::yield_context yield);
	void echo_reader(boost::asio::yield_context yield);
	void process_inbound_frame(inbound_t::iterator it);
	inbound_t::iterator drop_inbound_frame(inbound_t::iterator it);
	void process_outbound_frames();
	void send_outbound_reply(icmp_reply &reply);
};
