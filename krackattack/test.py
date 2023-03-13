from scapy.all import *

ps = sniff(count=1, timeout=0.5, lfilter=lambda p: p.haslayer(Dot11Beacon), iface=['wlan1'])
print(ps)