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

interruptible_loop::interruptible_loop(boost::asio::io_service &io) :
	io_(io), timer_(io),
	stopped_(false), interrupted_(false), yield_(NULL) {
}

void interruptible_loop::start(boost::asio::io_service &io_) {
	asio::spawn(io_, boost::bind(&interruptible_loop::main_loop_caller, this, _1));
}

void interruptible_loop::interrupt() {
	assert(!interrupted_);
	interrupted_ = true;
	timer_.cancel();
	assert(interrupted_);
	interrupted_ = false;
}

void interruptible_loop::stop() {
	stopped_ = true;
	timer_.cancel();
}

bool interruptible_loop::timer_wait() {
	boost::system::error_code ec;
	timer_.async_wait(yield[ec]);
	if (stopped_) {
		throw stopped();
	}
	if (interrupted_) {
		assert(ec == boost::asio::error::operation_aborted);
		return false;
	}
	if (ec) {
		// Not expected
		throw boost::system::system_error(ec);
	}
	return true;
}

void interruptible_loop::main_loop_caller(boost::asio::yield_context yield) {
	try {
		main_loop(yield);
		assert(!stopped_);
	} catch (const stopped &exc) {
		assert(stopped_);
	}
}
