#!/bin/bash
set -e

# Interfaces that are used
INTERNET=eth1
#INTERNET=wlp5s0
REPEATER=wlan0

echo ""
echo "[ ] Configuring IP address of malicious AP"
ip addr del 192.168.100.1/24 dev wlan0 2> /dev/null || true
ip addr add 192.168.100.1/24 dev $REPEATER

echo "[ ] Enabling IP forwaring"
sysctl net.ipv4.ip_forward=1 > /dev/null

echo "[ ] Enabling NAT"
iptables -F
iptables -t nat -A POSTROUTING -o $INTERNET -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $REPEATER -o $INTERNET -j ACCEPT

echo "[ ] Starting DHCP and DNS service"

echo ""
dnsmasq -d -C dnsmasq.conf

