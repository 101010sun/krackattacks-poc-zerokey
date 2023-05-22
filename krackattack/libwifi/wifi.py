from scapy.all import * 
from datetime import datetime
import sys, os, socket, struct, time, argparse, heapq, subprocess, atexit, select, textwrap


IEEE_TLV_TYPE_SSID    = 0
IEEE_TLV_TYPE_CHANNEL = 3
IEEE_TLV_TYPE_RSN     = 48
IEEE_TLV_TYPE_CSA     = 37
IEEE_TLV_TYPE_VENDOR  = 221

IEEE80211_RADIOTAP_RATE = (1 << 2)
IEEE80211_RADIOTAP_CHANNEL = (1 << 3)
IEEE80211_RADIOTAP_TX_FLAGS = (1 << 15)
IEEE80211_RADIOTAP_DATA_RETRIES = (1 << 17)

#### Basic output and logging functionality ####
ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = { "gray"  : "\033[0;37m",
               "green" : "\033[0;32m",
               "orange": "\033[0;33m",
               "red"   : "\033[0;31m" }

global_log_level2 = INFO

def log(level, msg, color=None, showtime=True):
	if level < global_log_level2: return
	if level == DEBUG   and color is None: color="gray"
	if level == WARNING and color is None: color="orange"
	if level == ERROR   and color is None: color="red"
	print((datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + "\033[1;0m")

def set_global_log_level2(value):
	global global_log_level2
	global_log_level2 = value

# 取得 beacon frame 的 ssid func.
def get_tlv_value(p, typee):
	if not p.haslayer(Dot11Elt): return None
	el = p[Dot11Elt]
	while isinstance(el, Dot11Elt):
		if el.ID == typee:
			return el.info.decode()
		el = el.payload
	return None

#### Utility ####
def call_macchanger(iface, macaddr):
	try:
		subprocess.check_output(["macchanger", "-m", macaddr, iface])
	except subprocess.CalledProcessError as err:
		if not "It's the same MAC!!" in err.output.decode():
			print(err.output.decode())
			raise

def set_mac_address(iface, macaddr):
	subprocess.check_output(["ifconfig", iface, "down"])
	call_macchanger(iface, macaddr)
	subprocess.check_output(["ifconfig", iface, "up"])

#### Packet Processing Functions ####
def xorstr(lhs, rhs):
	return "".join([chr(ord(lb) ^ ord(rb)) for lb, rb in zip(lhs, rhs)])

def dot11_get_seqnum(p):
	# .... .... .... (....)對齊用
	return p[Dot11].SC >> 4

def payload_to_iv(payload):
	iv0 = payload[0]
	iv1 = payload[1]
	wepdata = payload[4:8]

	return orb(iv0) + (orb(iv1) << 8) + (struct.unpack(">I", wepdata)[0] << 16)

def dot11_get_iv(p):
	"""
	Assume it's a CCMP frame. Old scapy can't handle Extended IVs.
	This code only works for CCMP frames.
	"""
	if Dot11CCMP in p:
		payload = raw(p[Dot11CCMP])
		return payload_to_iv(payload)

	elif Dot11TKIP in p:
		# Scapy uses a heuristic to differentiate CCMP/TKIP and this may be wrong.
		# So even when we get a Dot11TKIP frame, we should treat it like a Dot11CCMP frame.
		payload = raw(p[Dot11TKIP])
		return payload_to_iv(payload)

	if Dot11CCMP in p:
		payload = raw(p[Dot11CCMP])
		return payload_to_iv(payload)
	elif Dot11TKIP in p:
		payload = raw(p[Dot11TKIP])
		return payload_to_iv(payload)
	elif Dot11Encrypted in p:
		payload = raw(p[Dot11Encrypted])
		return payload_to_iv(payload)

	elif Dot11WEP in p:
		wep = p[Dot11WEP]
		if wep.keyid & 32:
			# FIXME: Only CCMP is supported (TKIP uses a different IV structure)
			return orb(wep.iv[0]) + (orb(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
		else:
			return orb(wep.iv[0]) + (orb(wep.iv[1]) << 8) + (orb(wep.iv[2]) << 16)

	elif p.FCfield & 0x40:
		return payload_to_iv(p[Raw].load)

	else:
		return None

def dot11_get_tid(p):
	if p.haslayer(Dot11QoS):
		return ord(bytes(p[Dot11QoS])[0]) & 0x0F
	return 0

def dot11_is_group(p):
	return p.addr1 == "ff:ff:ff:ff:ff:ff"

def get_eapol_msgnum(p):
	# key information 對應位置
	FLAG_PAIRWISE = 0b0000001000
	FLAG_ACK      = 0b0010000000
	FLAG_SECURE   = 0b1000000000

	if not p.haslayer(EAPOL): return 0
	keyinfo = bytes(p[EAPOL])[5:7]
	flags = struct.unpack(">H", keyinfo)[0]
	# pairwise 都是 1
	if flags & FLAG_PAIRWISE:
		# ACK 為 1，sent by server
		if flags & FLAG_ACK:
			# 如果有加密，則為 msg3
			if flags & FLAG_SECURE: return 3
			else: return 1
		# ACK 為 0，sent by client
		else:
			keydatalen = struct.unpack(">H", bytes(p[EAPOL].load[93:95]))[0]
			# msg4 不會有任何 data
			if keydatalen == 0: return 4
			else: return 2
	return 0

def get_eapol_replaynum(p):
	return struct.unpack(">Q", p[EAPOL].load[5:13])[0]

def set_eapol_replaynum(p, value):
	p[EAPOL].load = p[EAPOL].load[:5] + struct.pack(">Q", value) + p[EAPOL].load[13:]
	return p

def dot11_to_str(p):
	EAP_CODE = {1: "Request"}
	EAP_TYPE = {1: "Identity"}
	DEAUTH_REASON = {1: "Unspecified", 2: "Prev_Auth_No_Longer_Valid/Timeout", 3: "STA_is_leaving", 4: "Inactivity", 6: "Unexp_Class2_Frame",
		7: "Unexp_Class3_Frame", 8: "Leaving", 15: "4-way_HS_timeout"}
	dict_or_str = lambda d, v: d.get(v, str(v))
	if p.type == 0:
		if p.haslayer(Dot11Beacon):     return "Beacon(seq=%d, TSF=%d)" % (dot11_get_seqnum(p), p[Dot11Beacon].timestamp)
		if p.haslayer(Dot11ProbeReq):   return "ProbeReq(seq=%d)" % dot11_get_seqnum(p)
		if p.haslayer(Dot11ProbeResp):  return "ProbeResp(seq=%d)" % dot11_get_seqnum(p)
		if p.haslayer(Dot11Auth):       return "Auth(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11Auth].status)
		if p.haslayer(Dot11Deauth):     return "Deauth(seq=%d, reason=%s)" % (dot11_get_seqnum(p), dict_or_str(DEAUTH_REASON, p[Dot11Deauth].reason))
		if p.haslayer(Dot11AssoReq):    return "AssoReq(seq=%d)" % dot11_get_seqnum(p)
		if p.haslayer(Dot11ReassoReq):  return "ReassoReq(seq=%d)" % dot11_get_seqnum(p)
		if p.haslayer(Dot11AssoResp):   return "AssoResp(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11AssoResp].status)
		if p.haslayer(Dot11ReassoResp): return "ReassoResp(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11ReassoResp].status)
		if p.haslayer(Dot11Disas):      return "Disas(seq=%d)" % dot11_get_seqnum(p)
		if p.subtype == 13:      return "Action(seq=%d)" % dot11_get_seqnum(p)
	elif p.type == 1:
		if p.subtype ==  9:      return "BlockAck"
		if p.subtype == 11:      return "RTS"
		if p.subtype == 13:      return "Ack"
	elif p.type == 2:
		if p.haslayer(Dot11WEP): return "EncryptedData(seq=%d, IV=%d)" % (dot11_get_seqnum(p), dot11_get_iv(p))
		if p.subtype == 4:       return "Null(seq=%d, sleep=%d)" % (dot11_get_seqnum(p), p.FCfield & 0x10 != 0)
		if p.subtype == 12:      return "QoS-Null(seq=%d, sleep=%d)" % (dot11_get_seqnum(p), p.FCfield & 0x10 != 0)
		if p.haslayer(EAPOL):
			if get_eapol_msgnum(p) != 0: return "EAPOL-Msg%d(seq=%d,replay=%d)" % (get_eapol_msgnum(p), dot11_get_seqnum(p), get_eapol_replaynum(p))
			elif p.haslayer(EAP):return "EAP-%s,%s(seq=%d)" % (dict_or_str(EAP_CODE, p[EAP].code), dict_or_str(EAP_TYPE, p[EAP].type), dot11_get_seqnum(p))
			else:                return repr(p)
		if p.haslayer(Dot11CCMP): return "EncryptedData(seq=%d)" % dot11_get_seqnum(p)
	return repr(p)			

def construct_csa(channel, count=1):
	switch_mode = 1			# STA should not Tx untill switch is completed
	new_chan_num = channel	# Channel it should switch to
	switch_count = count	# Immediately make the station switch
	# Contruct the IE
	payload = struct.pack("<BBB", switch_mode, new_chan_num, switch_count)
	return Dot11Elt(ID=IEEE_TLV_TYPE_CSA, info=payload)

def append_csa(p, channel, count=1):
	p = p.copy()
	el = p[Dot11Elt]
	prevel = None
	while isinstance(el, Dot11Elt):
		prevel = el
		el = el.payload
	prevel.payload = construct_csa(channel, count)
	return p


#### Man-in-the-middle Code ####
class MitmSocket(L2Socket):
	def __init__(self, dumpfile=None, strict_echo_test=False, **kwargs):
		super(MitmSocket, self).__init__(**kwargs)
		self.pcap = None
		if dumpfile:
			self.pcap = PcapWriter("%s.%s.pcap" % (dumpfile, self.iface), append=False, sync=True)
		self.strict_echo_test = strict_echo_test

	def set_channel(self, channel):
		subprocess.check_output(["iw", self.iface, "set", "channel", str(channel)])

	def get_channel_hex(self, channel):
		return '\\x' + hex(channel)[2:].zfill(2)

	def send(self, p, set_radio, channel):
		# 所有送出去的封包都要加 radiotap
		p[Dot11].FCfield |= 0x00
		if(set_radio):
			rt = RadioTap(len=18,
				present='Flags+Rate+Channel+dBm_AntSignal+Antenna', 
				notdecoded='\x00\x6c' + self.get_channel_hex(channel) + '\xc0\x00\xa0\xc0\x00\x00')
			L2Socket.send(self, rt/p)
			if self.pcap: self.pcap.write(rt/p)
			log(WARNING, "%s: Injected frame %s" % (self.iface, dot11_to_str(p)))
		else:
			L2Socket.send(self, p)
			if self.pcap: self.pcap.write(p)
			log(WARNING, "%s: Injected frame %s" % (self.iface, dot11_to_str(p)))

	def _strip_fcs(self, p):
		# radiotap header flags 0x00...0: no used FCS failed
		# .present is flagsfield
		if p[RadioTap].present & 2 != 0 and not p.haslayer(Dot11FCS):
			rawframe = raw(p[RadioTap])
			pos = 8 # FCS 在 frame 開頭後第 9 bytes 的地方
			while ord(rawframe[pos - 1]) & 0x80 != 0: pos += 4
			# If the TSFT field is present, it must be 8-bytes aligned
			if p[RadioTap].present & 1 != 0:
				pos += (8 - (pos % 8))
				pos += 8
			# radiotap flag & 0x10
			if rawframe[pos] & 0x10 != 0:
				try:
					# FCS 在 frame 的最後 4 bytes
					return Dot11(raw(p[Dot11FCS])[:-4])
				except:
					return None
				
		return p[Dot11]

	def recv(self, x=MTU):
		p = L2Socket.recv(self, x)
		if p == None: 
			return None, None
		if p.getlayer(Dot11) == None:
			return None, None
		
		if self.pcap: self.pcap.write(p)
		# Don't care about control frames
		if p.type == 1:
			log(ALL, "%s: ignoring control frame %s" % (self.iface, dot11_to_str(p)))
			return None, None

		# 1. Radiotap monitor mode header is defined in ieee80211_add_tx_radiotap_header: TX_FLAGS, DATA_RETRIES, [RATE, MCS, VHT, ]
		# 2. Radiotap header for normal received frames is defined in ieee80211_add_rx_radiotap_header: FLAGS, CHANNEL, RX_FLAGS, [...]
		# 3. Beacons generated by hostapd and recieved on virtual interface: TX_FLAGS, DATA_RETRIES
		#
		# Conclusion: if channel flag is not present, but rate flag is included, then this could be an echoed injected frame.
		# Warning: this check fails to detect injected frames captured by the other interface (due to proximity of transmittors and capture effect)
		radiotap_possible_injection = (p[RadioTap].present & IEEE80211_RADIOTAP_CHANNEL == 0) and not (p[RadioTap].present & IEEE80211_RADIOTAP_RATE == 0)

		# Hack: ignore frames that we just injected and are echoed back by the kernel. Note that the More Data flag also
		#	allows us to detect cross-channel frames (received due to proximity of transmissors on different channel)
		if p[Dot11].FCfield & 0x20 != 0 and (not self.strict_echo_test or radiotap_possible_injection):
			log(DEBUG, "%s: ignoring echoed frame %s (0x%02d, present=%08d, strict=%d)" % (self.iface, dot11_to_str(p), p[Dot11].FCfield, p[RadioTap].present, radiotap_possible_injection))
			return None, None
		else:
			log(ALL, "%s: Received frame: %s" % (self.iface, dot11_to_str(p)))
		result = self._strip_fcs(p)
		return result, p

	def close(self):
		if self.pcap: self.pcap.close()
		super(MitmSocket, self).close()
