from scapy.all import sniff, IP, TCP, UDP, wrpcap

packet_list = []

def packet_callback(packet):
    packet_list.append(packet)

    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"\nSource: {ip.src} -> Destination: {ip.dst}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"TCP | Src Port: {tcp.sport} | Dst Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"UDP | Src Port: {udp.sport} | Dst Port: {udp.dport}")

# Capture packets
print("Sniffing started...")
sniff(count=20, prn=packet_callback)

# Save packets
wrpcap("capture.pcap", packet_list)
print("Packets saved to capture.pcap")
