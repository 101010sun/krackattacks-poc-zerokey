from scapy.all import *

sniff(iface=['wlan1'], prn=lambda x: x.sniffed_on+": "+x.summary())