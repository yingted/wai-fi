#!/bin/bash
trap 'sudo kill $hostapd $dnsmasq $icmp_tap' EXIT INT QUIT TERM
sudo iw phy phy0 interface add wlp3s0v1 type station
sudo hostapd hostapd.conf & hostapd=$!
sudo ifconfig wlp3s0v1 192.168.9.1
sudo killall dnsmasq
sudo ./icmp_tap & icmp_tap=$!
sudo dnsmasq -d -ki wlp3s0v1 -i icmp0 -F 192.168.9.20,192.168.9.254,255.255.255.0,12h -F 192.168.10.20,192.168.10.254,255.255.255.0,12h & dnsmasq=$!
wait
trap - EXIT INT QUIT TERM
