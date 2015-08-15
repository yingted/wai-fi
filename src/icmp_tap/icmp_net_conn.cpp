#define BOOST_ASIO_HAVE_NONE
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
	cid_(cid),
	outbound_(*this),
	inbound_(*this, first),
	sig_conn_(inet.on_tap_frame_.connect(boost::bind(&icmp_net_conn::on_tap_frame, this, _1))),
	alive_(true) {
	outbound_.start();
	inbound_.start();
}

void icmp_net_conn::on_tap_frame(shared_ptr<const icmp_net::tap_frame_t> frame) {
	if (!alive_) {
		return;
	}
	cout << "on_tap_frame: read: " << frame->size() << " B" << endl;
	outbound_.enqueue_output(frame);
}

void icmp_net_conn::on_raw_frame(unique_ptr<icmp_net::raw_frame_t> &frame) {
	if (!alive_) {
		return;
	}
	cout << "on_raw_frame: echo: seq=" << frame->reply->seq << endl;
	inbound_.sliding_insert(frame);
	outbound_.enqueue_reply(frame);
}

void icmp_net_conn::stop() {
	alive_ = false;
	inbound_.stop();
	outbound_.stop();
	// Let's extend its life a bit
	auto sp = icmp_net_->conns_[cid_];
	icmp_net_->conns_.erase(cid_);
	assert(sp.use_count() == 1);
}
