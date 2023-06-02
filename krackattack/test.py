from scapy.all import * 

def send_80211_packet(destination_mac, from_mac, interface):
    # 创建L2Socket对象
    socket = L2Socket(iface=interface)

    # 构建要发送的封包
    packet = RadioTap() / Dot11(type=0, subtype=4, addr1=destination_mac, addr2=from_mac, addr3=from_mac) / Raw(load="Hello, target!")

    try:
        # 发送封包
        socket.send(packet)
        print("Packet sent successfully!")
    except Exception as e:
        print("Failed to send packet:", e)

# 指定要发送封包的目标MAC地址和网络接口
destination_mac = "bc:ee:7b:e7:ab:54"  # 替换为目标设备的MAC地址
from_mac = 'da:4a:77:65:f3:f5'
interface = "wlan0"  # 替换为您的网络接口名称

# 调用函数发送封包
send_80211_packet(destination_mac, from_mac, interface)