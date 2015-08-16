#pragma once

#ifdef __cplusplus
#include <boost/asio/steady_timer.hpp>
#include <boost/chrono/include.hpp>

typedef boost::asio::steady_timer boost_timer_t;
typedef boost_timer_t::clock_type boost_clock_t;
typedef boost_clock_t::time_point time_point_t;
#endif
