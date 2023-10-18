#!/usr/bin/env python3

import atexit
import logging
import argparse
from scapy.all import *
from libwifi import *
from detect_fakeap import FakeAP
from detect_krack import KRAckAttack

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

global_log_level = INFO

def fakeApCleanUp(attack: FakeAP):
    attack.stop()

def krackAttackCleanUp(attack: KRAckAttack):
    attack.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    # 必要的參數
    parser.add_argument(
        "nic_real_mon", help="Wireless monitor interface that will listen on the channel of the target AP.")
    parser.add_argument(
        "nic_real_clientack", help="Wireless monitor interface that will station on the channel of the target AP.")
    parser.add_argument(
        "nic_rogue_mon", help="Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.")
    parser.add_argument(
        "nic_rogue_ap", help="Wireless monitor interface that will run a rogue AP using a modified hostapd.")
    parser.add_argument("ssid", help="The SSID of the network to attack.")

    # 其他參數
    parser.add_argument(
        "-p", "--password", help="The password of the network to attack.")
    parser.add_argument(
        "-t", "--target", help="Specifically target the client with the given MAC address.")
    parser.add_argument(
        "-c", "--dump", help="Dump captured traffic to the pcap files <this argument name>.<nic>.pcap")
    parser.add_argument("-d", "--debug", action="count",
                        help="increase output verbosity", default=0)
    parser.add_argument(
        "--strict-echo-test", help="Never treat frames received from the air as echoed injected frames", action='store_true')
    parser.add_argument("--continuous-csa", action='store_true')
    parser.add_argument("--group", action='store_true')

    args = parser.parse_args()
    # Channel-based MitM detection
    global_log_level = max(ALL, global_log_level - args.debug)
    set_global_log_level2(max(ALL, global_log_level - args.debug))
    if args.password is not None:
        print("\n\t===[ channel-based MitM position by Mathy Vanhoef ]====\n")
        FakeAPAttack = FakeAP(args.nic_real_mon, args.nic_real_clientack, args.nic_rogue_ap,
                        args.nic_rogue_mon, args.ssid, args.password, args.group, args.target, args.dump, args.continuous_csa)
        atexit.register(fakeApCleanUp, args=(FakeAPAttack))
        FakeAPAttack.run(strict_echo_test=args.strict_echo_test)
    # KRACK detection
    global_log_level = max(ALL, global_log_level - args.debug)
    set_global_log_level2(max(ALL, global_log_level - args.debug))
    print(
        "\n\t===[ KRACK Attacks against Linux/Android by Mathy Vanhoef ]====\n")
    KrackAttack = KRAckAttack(args.nic_real_mon, args.nic_real_clientack,
                         args.nic_rogue_ap, args.nic_rogue_mon, args.ssid, args.target, args.dump)
    atexit.register(krackAttackCleanUp, args=(KrackAttack))
    KrackAttack.run(strict_echo_test=args.strict_echo_test)