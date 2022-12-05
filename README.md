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