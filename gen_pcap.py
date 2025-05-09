from scapy.all import Ether, IP, TCP, wrpcap

# 构造以太网帧
eth = Ether(dst="a0:88:c2:32:04:40", src="00:0c:29:4d:89:fc", type=0x0800)

# 构造IP数据包
ip = IP(dst="192.168.1.1", src="192.168.1.2")

# 构造TCP数据包
tcp = TCP(dport=80, sport=12345, flags="S")

# 将数据包拼接
packet = eth / ip / tcp

# 写入PCAP文件
wrpcap("output.pcap", [packet])

print("PCAP文件已创建，文件名为output.pcap")
