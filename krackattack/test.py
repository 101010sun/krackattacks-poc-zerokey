from scapy.all import *

ps = sniff(lfilter=lambda p: p.haslayer(Dot11Beacon), iface=['wlan1'])
print(ps)