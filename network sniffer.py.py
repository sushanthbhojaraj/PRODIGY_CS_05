from scapy.all import sniff, IP, TCP, UDP, Raw

# Callback function that gets called for each captured packet
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"\n📦 Packet:")
        print(f"🔸 Source IP: {src_ip}")
        print(f"🔸 Destination IP: {dst_ip}")
        print(f"🔸 Protocol: {proto} ({'TCP' if proto == 6 else 'UDP' if proto == 17 else 'Other'})")

        # Show TCP or UDP port numbers if available
        if TCP in packet:
            print(f"🔹 Source Port: {packet[TCP].sport}")
            print(f"🔹 Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"🔹 Source Port: {packet[UDP].sport}")
            print(f"🔹 Destination Port: {packet[UDP].dport}")

        # Print raw data if present
        if Raw in packet:
            data = packet[Raw].load
            try:
                print("🧾 Payload:", data.decode(errors='ignore'))
            except:
                print("🧾 Payload: (binary data)")

# Start sniffing (requires sudo/admin for most interfaces)
print("Starting packet sniffing... Press Ctrl+C to stop.\n")
sniff(prn=process_packet, store=False)
