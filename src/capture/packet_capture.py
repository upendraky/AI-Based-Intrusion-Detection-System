from scapy.all import sniff, IP, TCP, UDP


def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:
        protocol = str(packet[IP].proto)
        src_port = None
        dst_port = None

    print(
        f"SRC={src_ip} | "
        f"DST={dst_ip} | "
        f"PROTO={protocol} | "
        f"SPORT={src_port} | "
        f"DPORT={dst_port} | "
        f"SIZE={packet_size}"
    )


if __name__ == "__main__":
    interface = "en0"

    print("=" * 60)
    print("AI IDS - LIVE PACKET CAPTURE TEST")
    print("=" * 60)
    print(f"Interface: {interface}")
    print("Capture started...")
    print("Press CTRL+C to stop.")
    print("=" * 60)

    sniff(
        iface=interface,
        prn=process_packet,
        store=False
    )
