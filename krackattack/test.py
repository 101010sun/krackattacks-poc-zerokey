from scapy.all import *

ps = sniff(count=1, timeout=0.5, prn=lambda x: x.summary(), iface=['wlan1'])
print(ps)