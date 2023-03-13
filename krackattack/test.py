from scapy.all import *

ps = sniff(prn=lambda p: p.haslayer(Dot11Beacon), iface=['wlan1'])
print(ps)