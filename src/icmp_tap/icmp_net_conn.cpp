#include "types.h"
#include <iostream>
#include "icmp_net.h"
#include "icmp_net_conn.h"

using std::shared_ptr;
using std::cout;
using std::endl;

icmp_net_conn::icmp_net_conn(icmp_net &inet, connection_id cid, sequence_t first) :
	icmp_net_(inet),
	cid_(cid),
	outbound_(*this),
	inbound_(*this, first),
	sig_conn_(inet.on_tap_frame_.connect(boost::bind(&icmp_net_conn::on_tap_frame, this, _1))),
	alive_(true) {
	outbound_.start();
	inbound_.start();
}

void icmp_net_conn::on_tap_frame(shared_ptr<const tap_frame_t> frame) {
	if (!alive_) {
		return;
	}
	outbound_.enqueue_output(frame);
}

void icmp_net_conn::on_raw_frame(shared_ptr<raw_frame_t> frame) {
	if (!alive_) {
		return;
	}
	cout << "raw: echo: cid=" << frame->cid() << " seq=" << frame->orig_seq << endl;
	inbound_.sliding_insert(frame);
	outbound_.enqueue_reply(frame);
}

void icmp_net_conn::stop() {
	alive_ = false;
	inbound_.stop();
	outbound_.stop();
	// Let's extend its life a bit
	auto sp = icmp_net_.conns_[cid_];
	icmp_net_.conns_.erase(cid_);
	assert(sp.use_count() == 1);
}
