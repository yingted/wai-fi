#pragma once

#include "types.h"
#include <boost/asio.hpp>
#include <map>
#include <deque>
#include <memory>
#include "interruptible_loop.h"

class icmp_reply;
class icmp_net_conn;

class icmp_net_conn_outbound : public interruptible_loop {
public:
	typedef std::deque<std::shared_ptr<const tap_frame_t> > outbound_t;
	typedef std::map<sequence_t, std::shared_ptr<icmp_net_frame> > inbound_t;
	icmp_net_conn_outbound(icmp_net_conn &conn);
	void main_loop(boost::asio::yield_context yield) final;
	void enqueue_output(std::shared_ptr<const tap_frame_t> frame);
	void enqueue_reply(std::shared_ptr<raw_frame_t> frame);
private:
	void send_reply(icmp_reply &reply);
	icmp_net_conn &conn_;
	unsigned char queued_;
	outbound_t outbound_;
	inbound_t inbound_;
};
