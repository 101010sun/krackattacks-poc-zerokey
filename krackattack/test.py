from scapy.all import *

ps = sniff(count=100, timeout=10, lfilter=lambda p: p.haslayer(Dot11Beacon), prn=lambda x: x.summary(), iface=['wlan1'])
print(ps)