#!/bin/bash
sudo killall dnsmasq icmp_tap hostapd
cleanup() {
	echo exiting
	sudo kill $hostapd $dnsmasq $icmp_tap
	sudo killall dnsmasq icmp_tap hostapd
	sleep .1
	sudo kill -TERM $hostapd $dnsmasq $icmp_tap
	sleep .1
	sudo kill -9 $hostapd $dnsmasq $icmp_tap
}
trap 'cleanup' EXIT INT QUIT TERM
sudo iw phy phy0 interface add wlp3s0v1 type station
cat > hostapd.conf << EOF
interface=wlp3s0v1
driver=nl80211
ssid=icmp-test
channel=$(iwlist wlp3s0 channel | sed -n 's/.*Current.*Channel \([0-9]\+\).*/\1/p')
EOF
sudo hostapd hostapd.conf & hostapd=$!
sudo ifconfig wlp3s0v1 192.168.9.1
sudo ./icmp_tap & icmp_tap=$!
sudo dnsmasq -d -i wlp3s0v1 -i icmp0 -I lo -F 192.168.9.20,192.168.9.254,255.255.255.0,12h -F 192.168.10.20,192.168.10.254,255.255.255.0,12h & dnsmasq=$!
wait
trap - EXIT INT QUIT TERM
