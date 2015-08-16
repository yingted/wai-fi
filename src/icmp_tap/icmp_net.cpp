#include "types.h"
#include <iostream>
#include <linux/icmp.h>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include "tap.h"
#include "icmp_net.h"
#include "icmp_net_frame.h"
#include "icmp_net_conn.h"

using std::shared_ptr;
using std::make_shared;
using std::invalid_argument;
using std::cout;
using std::endl;
namespace asio = boost::asio;
using asio::yield_context;
using asio::ip::icmp;

icmp_net::icmp_net(const char *dev, int mtu) :
	io_(),
	tap_(std::move(*create_tap_dev(io_, dev))),
	raw_(io_, icmp::v4()) {
	tap_.native_non_blocking(true); // XXX

	{
		struct icmp_filter filt;
		filt.data = ~(1U << ICMP_ECHO);
		if (setsockopt(raw_.native(), IPPROTO_RAW, ICMP_FILTER, &filt, sizeof(filt)) < 0) {
			perror("setsockopt");
		}
	}

	ip_set_up(dev, mtu);

	asio::spawn(io_, boost::bind(&icmp_net::tap_reader, this, _1));
	asio::spawn(io_, boost::bind(&icmp_net::raw_reader, this, _1));
}

void icmp_net::tap_reader(yield_context yield) {
	for (;;) {
		static char buf[64 * 1024];
		ssize_t len = tap_.async_read_some(asio::buffer(buf), yield);
		cout << "tap: read: " << len << " B" << endl;
		shared_ptr<tap_frame_t> frame;
		try {
			frame = make_shared<tap_frame_t>(buf, len);
		} catch (const invalid_argument &exc) {
			cout << "make_shared<tap_frame_t>: " << exc.what() << endl;
			continue;
		}

		on_tap_frame_(std::const_pointer_cast<const tap_frame_t>(frame));
	}
}

void icmp_net::write_to_tap(const raw_frame_t &frame, yield_context yield) {
	ssize_t data_len = asio::buffer_size(frame.buffer());
	if (data_len) {
		ssize_t written = tap_.async_write_some(frame.buffer(), yield);
		cout << "tap: write: " << written << " of " << data_len << " B" << endl;
		if (written != data_len) {
			cout << "tap: write: wrong number of bytes written" << endl;
		}
	}
}

void icmp_net::write_to_raw(asio::const_buffers_1 buf, icmp_net::raw_t::endpoint_type dst, yield_context yield) {
	ssize_t send_len = asio::buffer_size(buf);
	ssize_t sent = raw_.async_send_to(buf, dst, MSG_DONTWAIT, yield);
	if (send_len != sent) {
		cout << "raw: sent " << sent << " instead of " << send_len << endl;
	} else {
		cout << "raw: sent " << sent << " to " << dst << endl;
	}
}

void icmp_net::raw_reader(yield_context yield) {
	for (;;) {
		static char buf[64 * 1024];
		ssize_t len = raw_.async_receive(asio::buffer(buf), yield);
		cout << "raw: read: " << len << " B" << endl;

		shared_ptr<raw_frame_t> frame;
		try {
			frame = make_shared<raw_frame_t>(buf, len);
		} catch (const invalid_argument &exc) {
			cout << "raw: make_shared<raw_frame_t>: " << exc.what() << endl;
			continue;
		}

		{
			assert(frame);
			assert(frame->reply);
			connection_id cid = frame->cid();
			bool new_conn = !conns_.count(cid);
			if (new_conn) {
				printf("raw: new connection to %s\n", inet_ntoa(*(in_addr *)&frame->reply->addr));
				conns_.emplace(cid, make_shared<icmp_net_conn>(*this, cid, frame->orig_seq));
			}
			conns_[cid]->on_raw_frame(frame);
		}
	}
}

void icmp_net::run() {
	io_.run();
}
