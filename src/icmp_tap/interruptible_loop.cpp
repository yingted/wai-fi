#include "types.h"
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include "interruptible_loop.h"

namespace asio = boost::asio;

interruptible_loop::interruptible_loop(asio::io_service &io) :
	io_(io), timer_(io), yield_(NULL),
	stopped_(false), interrupted_(false) {
}

interruptible_loop::~interruptible_loop() = default;

void interruptible_loop::start() {
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
	assert(yield_);
	boost::system::error_code ec;
	timer_.async_wait((*yield_)[ec]);
	if (stopped_) {
		throw stopped();
	}
	if (interrupted_) {
		assert(ec == asio::error::operation_aborted);
		return false;
	}
	if (ec) {
		// Not expected
		throw boost::system::system_error(ec);
	}
	return true;
}

void interruptible_loop::main_loop_caller(asio::yield_context yield) {
	try {
		main_loop(yield);
		assert(!stopped_);
	} catch (const stopped &exc) {
		assert(stopped_);
	}
}
