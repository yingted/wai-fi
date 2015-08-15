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
#include "icmp_net_conn_inbound.h"
#include "icmp_net_conn_outbound.h"

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
