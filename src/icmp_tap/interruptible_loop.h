#pragma once

#include "types.h"
#include <boost/asio/spawn.hpp>
#include <boost/asio.hpp>

class interruptible_loop {
public:
	interruptible_loop(boost::asio::io_service &io_);
	void start();
	void interrupt();
	void stop();
protected:
	void main_loop(boost::asio::yield_context yield);
	bool timer_wait();
	boost::asio::io_service &io_;
	boost_timer_t timer_;
	boost::asio::yield_context *yield_;
private:
	class stopped {};
	bool stopped_, interrupted_;
	void main_loop_caller(boost::asio::yield_context yield);
};
