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
#include <linux/icmp.h>
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

time_point_t icmp_net_frame::inbound_deadline() const {
	return reply->time + chrono::milliseconds(500);
}

time_point_t icmp_net_frame::outbound_deadline() const {
	return reply->time + chrono::seconds(150);
}

asio::const_buffers_1 icmp_net_frame::buffer() const {
	return asio::buffer(data_begin - buf.begin() + buf.data(), buf.end() - data_begin);
}

template<typename T>
string::const_iterator icmp_net_frame::read(string::const_iterator begin, T *&ptr) {
	if (buf.end() - begin < sizeof(*ptr)) {
		throw invalid_argument("packet too short");
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
	data_begin = read(begin + ip->ihl * 4, icmp);

	// Verify some fields
	unsigned short tot_len = ntohs(ip->tot_len);
	if (len != tot_len) {
		printf("Expected tot_len=%d, got tot_len=%d\n", len, tot_len);
		throw invalid_argument("invalid packet length");
	}
	if (icmp->type != ICMP_ECHO) {
		throw invalid_argument("unexpected ICMP packet type");
	}

	reply = make_shared<icmp_reply>(ip->saddr, ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
	printf("icmp_net_frame: id=%d seq=%d saddr=%s\n", reply->id, reply->seq, inet_ntoa(*(in_addr *)&reply->addr));
}
