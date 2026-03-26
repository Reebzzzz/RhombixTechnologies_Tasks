from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip = packet[IP]

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"[TCP] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"[UDP] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}")

sniff(prn=packet_callback, store=0)
