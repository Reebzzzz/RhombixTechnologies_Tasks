from scapy.all import sniff, wrpcap

packets = sniff(count=50)
wrpcap("capture.pcap", packets)
