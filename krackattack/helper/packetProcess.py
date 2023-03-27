import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import struct, subprocess
from . import logging

#### Packet Processing Functions ####

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

def set_monitor_ack_address(iface, macaddr, sta_suffix=None):
	"""Add a virtual STA interface for ACK generation. This assumes nothing takes control of this
	   interface, meaning it remains on the current channel."""
	sta_iface = iface + ("sta" if sta_suffix is None else sta_suffix)
	subprocess.call(["iw", sta_iface, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
	subprocess.check_output(["iw", iface, "interface", "add", sta_iface, "type", "managed"])
	call_macchanger(sta_iface, macaddr)
	subprocess.check_output(["ifconfig", sta_iface, "up"])

def xorstr(lhs, rhs):
	return "".join([chr(ord(lb) ^ ord(rb)) for lb, rb in zip(lhs, rhs)])

def dot11_get_seqnum(p):
	return p[Dot11].SC >> 4

def dot11_get_iv(p):
	"""Scapy can't handle Extended IVs, so do this properly ourselves"""
	if not p.haslayer(Dot11WEP):
		logging.log(logging.ERROR, "INTERNAL ERROR: Requested IV of plaintext frame")
		return 0

	wep = p[Dot11WEP]
	if wep.keyid & 32:
		return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
	else:
		return ord(str(wep.iv[0])) + (ord(str(wep.iv[1])) << 8) + (ord(str(wep.iv[2])) << 16)

def dot11_get_tid(p):
	if p.haslayer(Dot11QoS):
		return ord(str(p[Dot11QoS])[0]) & 0x0F
	return 0

def dot11_is_group(p):
	# TODO: Detect if multicast bit is set in p.addr1
	return p.addr1 == "ff:ff:ff:ff:ff:ff"

def get_eapol_msgnum(p):
	FLAG_PAIRWISE = 0b0000001000
	FLAG_ACK      = 0b0010000000
	FLAG_SECURE   = 0b1000000000

	if not p.haslayer(EAPOL): return 0

	keyinfo = str(p[EAPOL])[5:7]
	flags = struct.unpack(">H", keyinfo.encode())[0]
	if flags & FLAG_PAIRWISE:
		# 4-way handshake
		if flags & FLAG_ACK:
			# sent by server
			if flags & FLAG_SECURE: return 3
			else: return 1
		else:
			# sent by server
			# FIXME: use p[EAPOL.load] instead of str(p[EAPOL])
			keydatalen = struct.unpack(">H", str(p[EAPOL])[97:99].encode())[0]
			if keydatalen == 0: return 4
			else: return 2

	return 0

def get_eapol_replaynum(p):
	# FIXME: use p[EAPOL.load] instead of str(p[EAPOL])
	return struct.unpack(">Q", str(p[EAPOL])[9:17].encode())[0]

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
		if p.haslayer(Dot11WEP):        return "EncryptedData(seq=%d, IV=%d)" % (dot11_get_seqnum(p), dot11_get_iv(p))
		if p.subtype == 4:       return "Null(seq=%d, sleep=%d)" % (dot11_get_seqnum(p), p.FCfield & 0x10 != 0)
		if p.subtype == 12:      return "QoS-Null(seq=%d, sleep=%d)" % (dot11_get_seqnum(p), p.FCfield & 0x10 != 0)
		if p.haslayer(EAPOL):
			if get_eapol_msgnum(p) != 0: return "EAPOL-Msg%d(seq=%d,replay=%d)" % (get_eapol_msgnum(p), dot11_get_seqnum(p), get_eapol_replaynum(p))
			elif p.haslayer(EAP):       return "EAP-%s,%s(seq=%d)" % (dict_or_str(EAP_CODE, p[EAP].code), dict_or_str(EAP_TYPE, p[EAP].type), dot11_get_seqnum(p))
			else:                return repr(p)
	return repr(p)			

def construct_csa(channel, count=1):
	switch_mode = 1			# STA should not Tx untill switch is completed
	new_chan_num = channel	# Channel it should switch to
	switch_count = count	# Immediately make the station switch

	# Contruct the IE
	payload = struct.pack("<BBB", switch_mode, new_chan_num, switch_count)
	return Dot11Elt(ID = logging.IEEE_TLV_TYPE_CSA, info = payload)

def append_csa(p, channel, count=1):
	p = p.copy()

	el = p[Dot11Elt]
	prevel = None
	while isinstance(el, Dot11Elt):
		prevel = el
		el = el.payload

	prevel.payload = construct_csa(channel, count)

	return p

def get_tlv_value(p, typee):
	if not p.haslayer(Dot11Elt): return None
	el = p[Dot11Elt]
	while isinstance(el, Dot11Elt):
		if el.ID == typee:
			return el.info.decode()
		el = el.payload
	return None

def print_rx(level, name, p, color=None, suffix=None):
	if p[Dot11].type == 1: return
	if color is None and (p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas)): color="orange"
	logging(level, "%s: %s -> %s: %s%s" % (name, p.addr2, p.addr1, dot11_to_str(p), suffix if suffix else ""), color=color)

