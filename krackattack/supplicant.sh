#!/bin/bash
../wpa_supplicant/wpa_supplicant -D nl80211 -i wlan2 -c supplicant.conf $@
