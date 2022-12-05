This script is currently not actively supported. The documentation is also not complete.

Before running this script, you must compile hostapd. This only needs to be done once:

	  cd ../hostapd
	  cp defconfig .config
	  make -j 2
	  cd ../
	  ./build.sh
	  cd ./krackattack
	  ./enable_internet_forwarding.sh

Then you can exece this script. See [our video](https://youtu.be/Oh4WURZoR98?t=47) for example commands.

## Prerequisties
intall the following dependencies on Kali Linux:
 ```
$sudo apt update
$sudo apt install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils pip
```
install the following python package:
```
pip install --user mitm_channel_based
pip install scapy==2.3.3
pip install pycryptodome
```
## Description
```
KRAckAttack(args.nic_real_mon, args.nic_rogue_ap, args.nic_rogue_mon, args.ssid, args.target, args.dump, args.continuous_csa)
```
- nic_real_mon: nic_real, nic_real_clientack
- nic_rogue_ap: nic_rogue_ap
- nic_rogue_mon: nic_rogue_mon

krack-all-zero-tk.py KRAckAttack class confiure_interfaces()
define wifi interfaces ! (need modify this)
1. iw <nic_real> set type monitor
2. (沒特別指定的話) <nic_rogue_mon> = <nic_rogue_ap> + mon
3. iw <nic_rogue_ap> interface add <nic_rogue_mon> type monitor
4. iw <nic_rogue_mon> set type monitor
5. <nic_real_clientack> = <nic_real> + sta1
6. iw <nic_real> interface add <nic_real_clientack> type managed