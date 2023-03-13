from scapy.all import *

# lfilter=lambda p: p.haslayer(Dot11Beacon)
ps = sniff(count=100, timeout=30, lfilter=lambda p: p.haslayer(Dot11Beacon), prn=lambda x: x.summary(), iface=['wlan1'])
print(ps)