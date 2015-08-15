#pragma once

#include <string>
#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/coroutine/all.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/signals2.hpp>
#include <boost/signals2/connection.hpp>
#include <boost/ptr_container/ptr_set.hpp>
#include "types.h"
#include <map>
#include <deque>
#include "icmp_reply.h"
#include <linux/icmp.h>
#include <linux/ip.h>
#include <memory>
#include <stdexcept>

class icmp_net_conn;

struct icmp_net_frame {
	const std::string buf;
	struct iphdr *ip;
	struct icmphdr *icmp;
	std::string::const_iterator data_begin;
	std::unique_ptr<icmp_reply> reply;
	icmp_net_frame(const char *buf, int len);
	boost::asio::const_buffers_1 buffer() const;
	time_point_t inbound_deadline() const;
private:
	template<typename T>
	std::string::const_iterator read(std::string::const_iterator begin, T *&ptr);
};

class icmp_net {
public:
	typedef std::string tap_frame_t;
	typedef icmp_net_frame raw_frame_t;
	typedef boost::signals2::signal<void(std::shared_ptr<const tap_frame_t>)> on_tap_frame_t;
	icmp_net(const char *dev, int mtu);
	void run();
	void write_to_tap(const icmp_net::raw_frame_t &frame, boost::asio::yield_context yield);
	on_tap_frame_t on_tap_frame_;
	boost::asio::io_service io_;
	std::map<connection_id, std::shared_ptr<icmp_net_conn> > conns_;
private:
	boost::asio::posix::stream_descriptor tap_;
	boost::asio::ip::icmp::socket raw_;

	void tap_reader(boost::asio::yield_context yield);
	void raw_reader(boost::asio::yield_context yield);
};

class icmp_net_conn {
public:
	typedef unsigned short sequence_t; // must be unsigned
	icmp_net_conn(icmp_net &inet, connection_id cid, sequence_t first);
	void on_tap_frame(std::shared_ptr<const icmp_net::tap_frame_t> frame);
	void on_raw_frame(std::unique_ptr<icmp_net::raw_frame_t> &frame);
	typedef std::map<sequence_t, std::unique_ptr<icmp_net_frame> > inbound_t;
	typedef std::deque<std::shared_ptr<const icmp_net::tap_frame_t> > outbound_t;
private:
	icmp_net *const icmp_net_;
	outbound_t outbound_;
	inbound_t inbound_;
	boost::signals2::scoped_connection sig_conn_;
	boost_timer_t timer_;
	connection_id cid_;
	sequence_t next_i_;
	boost::asio::yield_context *yield_;
	unsigned char queued_;

	void inbound_sliding_insert(std::unique_ptr<icmp_net::raw_frame_t> &frame);
	void inbound_sliding_clear_half_below(sequence_t start);
	inbound_t::iterator inbound_sliding_earlier_elements(sequence_t start, time_point_t now, boost::function<void(inbound_t::iterator)> cb);
	void notify();
	void echo_reader(boost::asio::yield_context yield);
	void process_inbound_frame(inbound_t::iterator it);
	inbound_t::iterator drop_inbound_frame(inbound_t::iterator it);
	void process_outbound_frames();
	void send_outbound_reply(const icmp_reply &reply);
};
