from dataclasses import dataclass
from datetime import datetime

from scapy.layers.inet import IP, TCP, UDP


@dataclass
class ParsedPacket:
    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: str

    packet_size: int
    timestamp: datetime

    tcp_flags: int = 0
    tcp_header_length: int = 0
    tcp_window: int = 0
    tcp_segment_length: int = 0


class PacketParser:

    @staticmethod
    def parse(packet) -> ParsedPacket | None:

        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)

        # Use Scapy's actual capture timestamp
        if hasattr(packet, "time"):
            timestamp = datetime.fromtimestamp(float(packet.time))
        else:
            timestamp = datetime.now()

        if TCP in packet:

            tcp = packet[TCP]

            return ParsedPacket(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(tcp.sport),
                dst_port=int(tcp.dport),
                protocol="TCP",
                packet_size=packet_size,
                timestamp=timestamp,
                tcp_flags=int(tcp.flags),
                tcp_header_length=int(tcp.dataofs or 0) * 4,
                tcp_window=int(tcp.window),
                tcp_segment_length=len(tcp)
            )

        if UDP in packet:

            udp = packet[UDP]

            return ParsedPacket(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(udp.sport),
                dst_port=int(udp.dport),
                protocol="UDP",
                packet_size=packet_size,
                timestamp=timestamp,
                tcp_segment_length=len(udp)
            )

        return ParsedPacket(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            protocol=str(packet[IP].proto),
            packet_size=packet_size,
            timestamp=timestamp
        )