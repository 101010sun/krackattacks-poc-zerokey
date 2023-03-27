import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import struct
from .helper import template
from .helper import logging

# 紀錄網路的config
class NetworkConfig():
	def __init__(self, password):
		self.ssid = None
		self.real_channel = None
		self.group_cipher = None
		self.wpavers = 0
		self.pairwise_ciphers = set()
		self.akms = set()
		self.wmmenabled = 0
		self.capab = 0
		self.password = password
		self.group = logging.group
		
	# 檢查 beacon frame MAC 層是否包含 RSNE 訊息，沒有就代表非使用 RSN 網路 (為WEP)
	def is_wparsn(self):
		return not self.group_cipher is None and self.wpavers > 0 and \
			len(self.pairwise_ciphers) > 0 and len(self.akms) > 0

	# 解析 RSN 內容
	def parse_wparsn(self, wparsn):
		# group 加密演算法
		self.group_cipher = ord(wparsn.decode('unicode_escape')[5])
        # 處理 c 語言的struct, H: unsigned short return python integer; <: little-endian
		num_pairwise = struct.unpack("<H", wparsn[6:8])[0]
		pos = wparsn[8:]
		for i in range(num_pairwise):
			self.pairwise_ciphers.add(ord(pos.decode('unicode_escape')[3]))
			pos = pos[4:]
        # 取出 akm 數量, (authentication and key management, akm)
		num_akm = struct.unpack("<H", pos[:2])[0]
		# 取出 akm suite list
		pos = pos[2:]
		for i in range(num_akm):
			self.akms.add(ord(pos.decode('unicode_escape')[3]))
			pos = pos[4:]
		# RSN capabilities
		if len(pos) >= 2:
			self.capab = struct.unpack("<H", pos[:2])[0]

	def from_beacon(self, p):
		el = p[Dot11Elt]
		while isinstance(el, Dot11Elt):
			if el.ID == logging.IEEE_TLV_TYPE_SSID:
				self.ssid = el.info.decode('unicode_escape')
			elif el.ID == logging.IEEE_TLV_TYPE_CHANNEL:
				self.real_channel = ord(el.info.decode('unicode_escape')[0])
			elif el.ID == logging.IEEE_TLV_TYPE_RSN:
				self.parse_wparsn(el.info)
				self.wpavers |= 2
			elif el.ID == logging.IEEE_TLV_TYPE_VENDOR and el.info.decode('unicode_escape')[:4] == "\x00\x50\xf2\x01":
				self.parse_wparsn(el.info[4:])
				self.wpavers |= 1
			elif el.ID == logging.IEEE_TLV_TYPE_VENDOR and el.info.decode('unicode_escape')[:4] == "\x00\x50\xf2\x02":
				self.wmmenabled = 1

			el = el.payload

	def find_rogue_channel(self):
		# 強盜 AP 頻道設置不是在 1 就是 11
		self.rogue_channel = 1 if self.real_channel >= 6 else 11
	
	# hostapd.confg寫檔 
	def write_config(self, iface):
		TEMPLATE = template.TEMPLATE
		akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
		ciphers2str = {2: "TKIP", 4: "CCMP"}
		return TEMPLATE.format(
			iface = iface,
			ssid = self.ssid,
			password = self.password,
			channel = self.rogue_channel,
			wpaver = self.wpavers,
			akms = " ".join([akm2str[idx] for idx in self.akms]),
			pairwise = " ".join([ciphers2str[idx] for idx in self.pairwise_ciphers]),
			ptksa_counters = (self.capab & 0b001100) >> 2,
			gtksa_counters = (self.capab & 0b110000) >> 4,
			wmmadvertised = int(self.group),
			wmmenabled = self.wmmenabled)
