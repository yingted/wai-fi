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

class icmp_net_conn;

class icmp_net_conn_outbound : public interruptible_loop {
public:
	typedef std::deque<std::shared_ptr<const tap_frame_t> > outbound_t;
	icmp_net_conn_outbound(icmp_net_conn &conn);
	void main_loop(boost::asio::yield_context yield);
	void enqueue_output(std::shared_ptr<const tap_frame_t> frame);
	void enqueue_reply(std::shared_ptr<raw_frame_t> &frame);
private:
	void send_reply(icmp_reply &reply);
	icmp_net_conn &conn_;
	unsigned char queued_;
	outbound_t outbound_;
};
