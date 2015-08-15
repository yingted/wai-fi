#pragma once

#include "types.h"
#include <boost/asio.hpp>
#include <memory>

std::unique_ptr<boost::asio::posix::stream_descriptor> create_tap_dev(boost::asio::io_service &io, const char *dev);
void ip_set_up(const char *dev, int mtu);
