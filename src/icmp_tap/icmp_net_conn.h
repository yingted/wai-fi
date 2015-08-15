#pragma once

#include "types.h"
#include <boost/coroutine/all.hpp>
#include <boost/signals2/connection.hpp>
#include <memory>
#include "icmp_net.h"
#include "icmp_net_conn_inbound.h"
#include "icmp_net_conn_outbound.h"

class icmp_net_conn {
public:
	icmp_net_conn(icmp_net &inet, connection_id cid, sequence_t first);
	void on_raw_frame(std::shared_ptr<raw_frame_t> &frame);
	icmp_net &icmp_net_;
	const connection_id cid_;
	void stop();
private:
	icmp_net_conn_outbound outbound_;
	icmp_net_conn_inbound inbound_;
	boost::signals2::scoped_connection sig_conn_;
	bool alive_;
	void on_tap_frame(std::shared_ptr<const tap_frame_t> frame);
};
