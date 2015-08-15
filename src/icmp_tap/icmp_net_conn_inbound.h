#pragma once

#include "types.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/coroutine/all.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/signals2.hpp>
#include <boost/signals2/connection.hpp>
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

class icmp_net_conn_inbound : public interruptible_loop {
public:
	typedef std::map<sequence_t, std::shared_ptr<icmp_net_frame> > inbound_t;
	icmp_net_conn_inbound(icmp_net_conn &conn, sequence_t next_i);
	void main_loop(boost::asio::yield_context yield);
	void sliding_insert(std::shared_ptr<raw_frame_t> &frame);
private:
	void sliding_clear_half_below(sequence_t start);
	inbound_t::iterator sliding_earlier_elements(sequence_t start, time_point_t now, boost::function<void(inbound_t::iterator)> cb);
	void process_frame(inbound_t::iterator it);
	inbound_t::iterator drop_frame(inbound_t::iterator it);
	icmp_net_conn &conn_;
	sequence_t next_i_;
	inbound_t inbound_;
};
