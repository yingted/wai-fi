#pragma once

#include <boost/asio.hpp>

boost::asio::posix::stream_descriptor create_tap_dev(boost::asio::io_service &io, char *dev);
void ip_set_up(char *dev, int mtu);
