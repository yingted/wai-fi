#include "types.h"
#include <algorithm>
#include <iostream>
#include <limits.h>
#include <linux/icmp.h>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include "inet_checksum.h"
#include "icmp_net.h"
#include "icmp_reply.h"
#include "icmp_net_frame.h"
#include "icmp_net_conn.h"
#include "interruptible_loop.h"
#include "icmp_net_conn_outbound.h"
#include <icmp_net_defs.h>

using std::shared_ptr;
using std::cout;
using std::endl;
namespace asio = boost::asio;
namespace chrono = std::chrono;
using asio::yield_context;

icmp_net_conn_outbound::icmp_net_conn_outbound(icmp_net_conn &conn) :
	interruptible_loop(conn.icmp_net_.io_),
	conn_(conn) {
}

void icmp_net_conn_outbound::main_loop(yield_context yield) {
	for (;;) {
		time_point_t now = chrono::steady_clock::now();

		// TODO improve the performance of all the sliding window stuff
		for (auto it = inbound_.begin(); it != inbound_.end();) {
			if (it->second->outbound_deadline() <= now) {
				cout << "outbound: timing out seq=" << it->first << endl;
				it = inbound_.erase(it);
			} else {
				++it;
			}
		}
		std::vector<shared_ptr<icmp_net_frame> > replies;
		for (const auto &it : inbound_) {
			replies.push_back(it.second);
		}
		int16_t origin = 0;
		{
			auto max_it = std::max_element(replies.begin(), replies.end(), [](shared_ptr<icmp_net_frame> a, shared_ptr<icmp_net_frame> b) {
				return a->reply->time < b->reply->time;
			});
			if (max_it != replies.end()) {
				origin = (*max_it)->orig_seq;
			}
		}
		std::sort(replies.begin(), replies.end(), [=](shared_ptr<icmp_net_frame> a, shared_ptr<icmp_net_frame> b) {
			return ((int16_t)a->orig_seq - origin) < ((int16_t)b->orig_seq - origin);
		});
		const static size_t max_replies = ICMP_NET_QSIZE;
		static_assert((ICMP_NET_QSIZE & -ICMP_NET_QSIZE) == ICMP_NET_QSIZE, "Invalid ICMP qsize");
		if (replies.size() > max_replies) {
			cout << "outbound: overflowing " << (replies.size() - max_replies) << " packets" << endl;
			replies = {replies.end() - max_replies, replies.end()};
		}
		queued_ = std::max<long>(0, std::min<long>(UCHAR_MAX, (long)outbound_.size() - (long)replies.size()));
		for (const auto &frame : replies) {
			if (outbound_.empty()) {
				break;
			}
			send_reply(frame);
			inbound_.erase(frame->orig_seq);
		}
		timer_.expires_at(time_point_t::max());
		if (!timer_wait()) {
			continue;
		}
	}

	cout << "outbound: closing connection " << conn_.cid_ << endl;
	conn_.stop();
}

void icmp_net_conn_outbound::send_reply(std::shared_ptr<raw_frame_t> in_frame) {
	icmp_reply &reply = *in_frame->reply;
	shared_ptr<const tap_frame_t> frame;
	{
		auto it = outbound_.begin();
		if (it == outbound_.end()) {
			return;
		}
		frame = *it;
		outbound_.erase(it);
	}

	cout
		<< "outbound: replying id=" << reply.id
		<< " seq=" << in_frame->orig_seq
		<< " saddr=" << inet_ntoa(*(in_addr *)&reply.addr)
		<< " queued=" << ((int)queued_)
		<< " len=" << frame->size()
		<< endl;

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

	{
		struct icmp_net_in_hdr hdr;
		static_assert(sizeof(hdr) == 4, "Incorrect header size");
		memset(&hdr, 0, sizeof(hdr));
		hdr.hdr.device_id = htons(in_frame->device_id);
		hdr.queued = queued_;

		memcpy(out, &hdr, sizeof(hdr));
		out += sizeof(hdr);
	}

	out = std::copy(frame->begin(), frame->end(), out);

	icmp->checksum = inet_checksum(icmp, out);

	icmp_net::raw_t::endpoint_type dst(asio::ip::address::from_string(inet_ntoa(*(in_addr *)&reply.addr)), reply.id);
	ssize_t send_len = out - buf;
	assert(((size_t)send_len) <= sizeof(buf));

	conn_.icmp_net_.write_to_raw(asio::buffer((const char *)buf, send_len), dst, *yield_);
}

void icmp_net_conn_outbound::enqueue_output(std::shared_ptr<const tap_frame_t> frame) {
	outbound_.push_back(frame);
	interrupt();
}

void icmp_net_conn_outbound::enqueue_reply(std::shared_ptr<raw_frame_t> frame) {
	assert(frame);
	cout << "outbound: enqueue_reply: seq=" << frame->orig_seq << endl;
	inbound_.emplace(frame->orig_seq, frame);
	interrupt();
}
