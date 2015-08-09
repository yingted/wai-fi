#!/bin/bash
sudo killall dnsmasq icmp_tap
cleanup() {
	echo exiting
	sudo kill $dnsmasq $icmp_tap || :
	sudo killall dnsmasq icmp_tap || :
	sleep .1
	sudo kill -TERM $dnsmasq $icmp_tap || :
	sleep .1
	sudo kill -9 $dnsmasq $icmp_tap || :
}
trap 'cleanup' EXIT INT QUIT TERM
set -e
sudo ./icmp_tap & icmp_tap=$!
sleep 1
sudo dnsmasq -d -i icmp0 -I lo -F 192.168.10.20,192.168.10.254,255.255.255.0,12h & dnsmasq=$!
wait $icmp_tap
cleanup
wait
trap - EXIT INT QUIT TERM
