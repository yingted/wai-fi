#include "types.h"
#include <iostream>
#include <arpa/inet.h>
#include <linux/icmp.h>
#include <limits.h>
#include <boost/asio.hpp>
#include <stdexcept>
#include "tap.h"
#include "inet_checksum.h"
#include "icmp_reply.h"
#include "icmp_net_frame.h"

using std::string;
using std::make_shared;
using std::cout;
using std::endl;
namespace asio = boost::asio;
namespace chrono = std::chrono;

invalid_frame::invalid_frame(const std::string &what)
	: std::runtime_error(what) {
}

time_point_t icmp_net_frame::inbound_deadline() const {
	return reply->time + chrono::milliseconds(500);
}

time_point_t icmp_net_frame::outbound_deadline() const {
	return reply->time + chrono::seconds(25);
}

asio::const_buffers_1 icmp_net_frame::buffer() const {
	return asio::buffer(data_begin - buf.begin() + buf.data(), buf.end() - data_begin);
}

template<typename T>
string::const_iterator icmp_net_frame::read(string::const_iterator begin, T *&ptr) {
	if (buf.end() - begin < sizeof(*ptr)) {
		throw invalid_frame("packet too short");
	}
	ptr = (T *)(begin - buf.begin() + buf.data());
	return begin + sizeof(*ptr);
}

icmp_net_frame::icmp_net_frame(const char *buf_arg, int len) :
	buf(buf_arg, len) {
	// Skip headers
	if (len == sizeof(buf)) {
		cout << "Warning: buffer full (" << len << " bytes)" << endl;
	}
	string::const_iterator begin = buf.begin();
	read(begin, ip);
	begin = read(begin + ip->ihl * 4, icmp);
	{
		uint16_t *device_id_p, *orig_seq_p;
		begin = read(begin, device_id_p);
		device_id = ntohs(*device_id_p);
		begin = read(begin, orig_seq_p);
		orig_seq = ntohs(*orig_seq_p);
	}
	data_begin = begin;

	// Verify some fields
	unsigned short tot_len = ntohs(ip->tot_len);
	if (len != tot_len) {
		printf("Expected tot_len=%d, got tot_len=%d\n", len, tot_len);
		throw invalid_frame("invalid packet length");
	}
	if (icmp->type != ICMP_ECHO) {
		throw invalid_frame("unexpected ICMP packet type");
	}

	reply = make_shared<icmp_reply>(ip->saddr, ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
	printf("icmp_net_frame: id=%d seq=%d(%d) from=%s\n", reply->id, orig_seq, reply->seq, inet_ntoa(*(in_addr *)&reply->addr));
}

connection_id icmp_net_frame::cid() const {
	connection_id ret;
	ret.device_id = device_id;
	ret.icmp_id = reply->id;
	return ret;
}

bool operator<(const connection_id &a, const connection_id &b) {
	return std::tie(a.icmp_id, a.device_id) < std::tie(b.icmp_id, b.device_id);
}

std::ostream &operator<<(std::ostream &os, const connection_id &cid) {
	return os << cid.icmp_id << '@' << cid.device_id;
}
