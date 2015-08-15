#include "types.h"
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
#include "tap.h"
#include "inet_checksum.h"
#include "icmp_net.h"
#include "icmp_reply.h"
#include "icmp_net_frame.h"
#include "icmp_net_conn.h"
#include "interruptible_loop.h"
#include "icmp_net_conn_outbound.h"

using std::string;
using std::shared_ptr;
using std::shared_ptr;
using std::make_shared;
using std::invalid_argument;
using std::cout;
using std::endl;
namespace asio = boost::asio;
namespace chrono = std::chrono;
using asio::yield_context;
using asio::ip::icmp;
using asio::io_service;
using boost::signals2::scoped_connection;

icmp_net_conn_outbound::icmp_net_conn_outbound(icmp_net_conn &conn) :
	interruptible_loop(conn.icmp_net_.io_),
	conn_(conn) {
}

void icmp_net_conn_outbound::main_loop(yield_context yield) {
	for (;;) {
		time_point_t now = chrono::steady_clock::now();
		std::vector<shared_ptr<icmp_net_frame> > replies;
		// TODO improve the performance of all the sliding window stuff
		for (const auto &it : inbound_) {
			shared_ptr<icmp_net_frame> frame = it.second;
			if (frame->outbound_deadline() <= now) {
				assert(false); //@remove it
			}
			replies.push_back(frame);
		}
		std::sort(replies.begin(), replies.end(), [](shared_ptr<icmp_net_frame> a, shared_ptr<icmp_net_frame> b) {
			return a->reply->time < b->reply->time;
		});
		queued_ = std::max<long>(0, std::min<long>(UCHAR_MAX, (long)outbound_.size() - (long)replies.size()));
		for (const auto &frame : replies) {
			if (outbound_.empty()) {
				break;
			}
			send_reply(*frame->reply);
			assert(false); //@erase it
		}
		timer_.expires_at(time_point_t::max());
		if (!timer_wait()) {
			continue;
		}
	}

	cout << "outbound: closing connection " << conn_.cid_ << endl;
	conn_.stop();
}

void icmp_net_conn_outbound::send_reply(icmp_reply &reply) {
	shared_ptr<const tap_frame_t> frame;
	{
		auto it = outbound_.begin();
		if (it == outbound_.end()) {
			return;
		}
		frame = *it;
		outbound_.erase(it);
	}

	printf("replying id=%d seq=%d saddr=%s\n", reply.id, reply.seq, inet_ntoa(*(in_addr *)&reply.addr));

	// XXX This depends on not doing IO between this and async_send_to
	static char buf[64 * 1024];
	char *out = buf;

	struct icmphdr *icmp = (struct icmphdr *)out;
	{
		out += sizeof(*icmp);
		icmp->type = ICMP_ECHOREPLY;
		icmp->code = 0;
		icmp->un.echo.id = htons(reply.id);
		icmp->un.echo.sequence = htons(reply.seq);
		icmp->checksum = 0;
	}

	*out++ = queued_;
	// padding
	*out++ = 0;

	out = std::copy(frame->begin(), frame->end(), out);

	icmp->checksum = inet_checksum(icmp, out);

	icmp_net::raw_t::endpoint_type dst(asio::ip::address::from_string(inet_ntoa(*(in_addr *)&reply.addr)), reply.id);
	ssize_t send_len = out - buf;
	assert(((size_t)send_len) <= sizeof(buf));

	conn_.icmp_net_.write_to_raw(asio::buffer((const char *)buf, send_len), dst, *yield_);
}

void icmp_net_conn_outbound::enqueue_output(std::shared_ptr<const tap_frame_t> frame) {
	assert(false); //@enqueue frame
	interrupt();
}

void icmp_net_conn_outbound::enqueue_reply(std::shared_ptr<raw_frame_t> &frame) {
	assert(false); //@enqueue frame
	interrupt();
}
