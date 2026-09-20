from scapy.all import IP, TCP, UDP

from src.parsing.packet_parser import PacketParser


print("=" * 60)
print("PACKET PARSER TEST")
print("=" * 60)


# TCP test packet
tcp_packet = (
    IP(
        src="172.20.10.2",
        dst="162.125.40.1"
    )
    /
    TCP(
        sport=63251,
        dport=443,
        flags="S",
        window=65535
    )
    /
    b"Hello"
)


parsed = PacketParser.parse(tcp_packet)


print("\nTCP PACKET")

print("Source IP:", parsed.src_ip)
print("Destination IP:", parsed.dst_ip)
print("Source Port:", parsed.src_port)
print("Destination Port:", parsed.dst_port)
print("Protocol:", parsed.protocol)
print("Packet Size:", parsed.packet_size)
print("TCP Flags:", parsed.tcp_flags)
print("TCP Header Length:", parsed.tcp_header_length)
print("TCP Window:", parsed.tcp_window)
print("TCP Segment Length:", parsed.tcp_segment_length)


# UDP test packet
udp_packet = (
    IP(
        src="172.20.10.2",
        dst="8.8.8.8"
    )
    /
    UDP(
        sport=50000,
        dport=53
    )
    /
    b"DNS TEST"
)


parsed_udp = PacketParser.parse(udp_packet)


print("\nUDP PACKET")

print("Source IP:", parsed_udp.src_ip)
print("Destination IP:", parsed_udp.dst_ip)
print("Source Port:", parsed_udp.src_port)
print("Destination Port:", parsed_udp.dst_port)
print("Protocol:", parsed_udp.protocol)
print("Packet Size:", parsed_udp.packet_size)

print("=" * 60)
