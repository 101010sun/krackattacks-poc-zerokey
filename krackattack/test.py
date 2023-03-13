from scapy.all import *

ps = sniff(count=100, timeout=10, prn=lambda x: x.summary(), iface=['wlan1'])
print(ps)