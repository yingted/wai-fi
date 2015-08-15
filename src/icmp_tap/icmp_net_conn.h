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
#include "interruptible_loop.h"

typedef unsigned short sequence_t; // must be unsigned

class icmp_net_conn;

class icmp_net_conn_outbound : public interruptible_loop {
public:
	typedef std::deque<std::shared_ptr<const icmp_net::tap_frame_t> > outbound_t;
	icmp_net_conn_outbound(icmp_net_conn &conn);
	void main_loop(boost::asio::yield_context yield);
private:
	void process_frames();
	void send_reply(icmp_reply &reply);
	icmp_net_conn &conn_;
	unsigned char queued_;
	outbound_t outbound_;
};

class icmp_net_conn_inbound : public interruptible_loop {
public:
	typedef std::map<sequence_t, std::unique_ptr<icmp_net_frame> > inbound_t;
	icmp_net_conn_inbound(icmp_net_conn &conn, sequence_t next_i);
	void main_loop(boost::asio::yield_context yield);
private:
	void sliding_insert(std::unique_ptr<icmp_net::raw_frame_t> &frame);
	void sliding_clear_half_below(sequence_t start);
	inbound_t::iterator sliding_earlier_elements(sequence_t start, time_point_t now, boost::function<void(inbound_t::iterator)> cb);
	void process_frame(inbound_t::iterator it);
	inbound_t::iterator drop_frame(inbound_t::iterator it);
	icmp_net_conn &conn_;
	sequence_t next_i_;
	inbound_t inbound_;
};

class icmp_net_conn {
public:
	icmp_net_conn(icmp_net &inet, connection_id cid, sequence_t first);
	void on_raw_frame(std::unique_ptr<icmp_net::raw_frame_t> &frame);
private:
	icmp_net *const icmp_net_;
	connection_id cid_;
	icmp_net_conn_outbound outbound_;
	icmp_net_conn_inbound inbound_;
	boost::signals2::scoped_connection sig_conn_;
	bool alive_;

	void stop();
	void on_tap_frame(std::shared_ptr<const icmp_net::tap_frame_t> frame);
};
