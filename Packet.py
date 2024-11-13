from scapy.all import sniff, IP, TCP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dest_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        print(f"Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {protocol}")

        # Check if the packet has a TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dest_port = tcp_layer.dport
            print(f"TCP Port: {src_port} -> {dest_port}")
        
        # Check if the packet has a Raw layer (for payload)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload[:50]}...")  # Show first 50 bytes of payload

    print("-" * 50)  # Separator for readability

# Start sniffing
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
