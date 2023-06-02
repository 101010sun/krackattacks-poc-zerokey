from scapy.all import * 

def send_packet(destination_mac, interface):
    # 创建L2Socket对象
    socket = L2Socket(iface=interface)

    # 构建要发送的封包
    packet = Ether(dst=destination_mac) / Raw(load="Hello, target!")

    try:
        # 发送封包
        socket.send(packet)
        print("Packet sent successfully!")
    except Exception as e:
        print("Failed to send packet:", e)

# 指定要发送封包的目标MAC地址和网络接口
destination_mac = "9a:8f:3c:6c:9d:2c"  # 替换为目标设备的MAC地址
interface = "wlan0"  # 替换为您的网络接口名称

# 调用函数发送封包
send_packet(destination_mac, interface)