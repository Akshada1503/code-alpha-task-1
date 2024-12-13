from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")

        # Check for TCP packets
        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")

        # Check for UDP packets
        elif packet.haslayer(UDP):
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"UDP Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")

def start_sniffing():
    print("Starting packet capture...")
    # Start sniffing the network, passing the callback function
    sniff(prn=packet_callback, store=0)

if _name_ == "_main_":
    start_sniffing()
