from scapy.all import *

def send_test_packet(interface):
    # 创建L2Socket对象
    socket = L2Socket(iface=interface)

    # 构建测试封包，这里使用一个简单的ARP请求作为示例
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.0.1")

    try:
        # 发送封包
        socket.send(packet)
        print("Packet sent successfully!")
    except Exception as e:
        print("Failed to send packet:", e)

# 指定要测试的网络接口
interface = "wlan0"  # 替换为您的网络接口名称

# 调用函数发送测试封包
send_test_packet(interface)
