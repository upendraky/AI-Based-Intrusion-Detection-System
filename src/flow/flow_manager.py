from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Tuple

import numpy as np


FlowKey = Tuple[str, str, int, int, str]


@dataclass
class PacketRecord:
    timestamp: datetime
    size: int
    direction: str

    tcp_flags: int = 0
    tcp_header_length: int = 0
    tcp_window: int = 0
    tcp_segment_length: int = 0


@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: datetime
    last_seen: datetime

    packets: list[PacketRecord] = field(default_factory=list)

    @property
    def total_packets(self) -> int:
        return len(self.packets)

    @property
    def total_bytes(self) -> int:
        return sum(packet.size for packet in self.packets)

    @property
    def forward_packets(self) -> int:
        return sum(
            packet.direction == "forward"
            for packet in self.packets
        )

    @property
    def backward_packets(self) -> int:
        return sum(
            packet.direction == "backward"
            for packet in self.packets
        )

    @property
    def forward_bytes(self) -> int:
        return sum(
            packet.size
            for packet in self.packets
            if packet.direction == "forward"
        )

    @property
    def backward_bytes(self) -> int:
        return sum(
            packet.size
            for packet in self.packets
            if packet.direction == "backward"
        )

    @property
    def forward_sizes(self) -> list:
        return [
            packet.size
            for packet in self.packets
            if packet.direction == "forward"
        ]

    @property
    def backward_sizes(self) -> list:
        return [
            packet.size
            for packet in self.packets
            if packet.direction == "backward"
        ]

    @property
    def all_sizes(self) -> list:
        return [
            packet.size
            for packet in self.packets
        ]

    @property
    def duration(self) -> float:
        return (
            self.last_seen - self.start_time
        ).total_seconds()

    @property
    def average_packet_size(self) -> float:
        if not self.packets:
            return 0.0

        return self.total_bytes / self.total_packets

    @property
    def flow_bytes_per_second(self) -> float:
        duration = self.duration

        if duration <= 0:
            return float(self.total_bytes)

        return self.total_bytes / duration

    @property
    def flow_packets_per_second(self) -> float:
        duration = self.duration

        if duration <= 0:
            return float(self.total_packets)

        return self.total_packets / duration

    @property
    def forward_iats(self) -> list:
        timestamps = [
            packet.timestamp
            for packet in self.packets
            if packet.direction == "forward"
        ]

        if len(timestamps) < 2:
            return []

        return [
            (
                timestamps[i] - timestamps[i - 1]
            ).total_seconds()
            for i in range(1, len(timestamps))
        ]

    @property
    def backward_iats(self) -> list:
        timestamps = [
            packet.timestamp
            for packet in self.packets
            if packet.direction == "backward"
        ]

        if len(timestamps) < 2:
            return []

        return [
            (
                timestamps[i] - timestamps[i - 1]
            ).total_seconds()
            for i in range(1, len(timestamps))
        ]

    @property
    def tcp_packets(self) -> list:
        return [
            packet
            for packet in self.packets
            if self.protocol == "TCP"
        ]

    @property
    def syn_count(self) -> int:
        return sum(
            bool(packet.tcp_flags & 0x02)
            for packet in self.tcp_packets
        )

    @property
    def psh_count(self) -> int:
        return sum(
            bool(packet.tcp_flags & 0x08)
            for packet in self.tcp_packets
        )

    @property
    def urg_count(self) -> int:
        return sum(
            bool(packet.tcp_flags & 0x20)
            for packet in self.tcp_packets
        )

    @property
    def forward_psh_count(self) -> int:
        return sum(
            packet.direction == "forward"
            and bool(packet.tcp_flags & 0x08)
            for packet in self.tcp_packets
        )

    @property
    def min_forward_segment_size(self) -> int:
        values = [
            packet.tcp_segment_length
            for packet in self.packets
            if packet.direction == "forward"
            and packet.tcp_segment_length > 0
        ]

        if not values:
            return 0

        return min(values)


class FlowManager:

    def __init__(self, inactivity_timeout: float = 5.0):
        """
        Manage active network flows.

        inactivity_timeout:
            Number of seconds after which a flow with no new
            packets is considered expired.
        """

        self.flows: Dict[FlowKey, NetworkFlow] = {}

        self.inactivity_timeout = inactivity_timeout

    def get_flow_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str
    ) -> FlowKey:

        return (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        )

    def get_reverse_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str
    ) -> FlowKey:

        return (
            dst_ip,
            src_ip,
            dst_port,
            src_port,
            protocol
        )

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        packet_size: int,
        timestamp: datetime | None = None,
        tcp_flags: int = 0,
        tcp_header_length: int = 0,
        tcp_window: int = 0,
        tcp_segment_length: int = 0
    ) -> NetworkFlow:

        if timestamp is None:
            timestamp = datetime.now()

        forward_key = self.get_flow_key(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        )

        reverse_key = self.get_reverse_key(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        )

        # ---------------------------------------------------------
        # Forward packet
        # ---------------------------------------------------------

        if forward_key in self.flows:

            flow = self.flows[forward_key]

            flow.last_seen = timestamp

            flow.packets.append(
                PacketRecord(
                    timestamp=timestamp,
                    size=packet_size,
                    direction="forward",
                    tcp_flags=tcp_flags,
                    tcp_header_length=tcp_header_length,
                    tcp_window=tcp_window,
                    tcp_segment_length=tcp_segment_length
                )
            )

            return flow

        # ---------------------------------------------------------
        # Backward packet
        # ---------------------------------------------------------

        if reverse_key in self.flows:

            flow = self.flows[reverse_key]

            flow.last_seen = timestamp

            flow.packets.append(
                PacketRecord(
                    timestamp=timestamp,
                    size=packet_size,
                    direction="backward",
                    tcp_flags=tcp_flags,
                    tcp_header_length=tcp_header_length,
                    tcp_window=tcp_window,
                    tcp_segment_length=tcp_segment_length
                )
            )

            return flow

        # ---------------------------------------------------------
        # New flow
        # ---------------------------------------------------------

        flow = NetworkFlow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            start_time=timestamp,
            last_seen=timestamp
        )

        flow.packets.append(
            PacketRecord(
                timestamp=timestamp,
                size=packet_size,
                direction="forward",
                tcp_flags=tcp_flags,
                tcp_header_length=tcp_header_length,
                tcp_window=tcp_window,
                tcp_segment_length=tcp_segment_length
            )
        )

        self.flows[forward_key] = flow

        return flow

    # -------------------------------------------------------------
    # TCP FLOW TERMINATION
    # -------------------------------------------------------------

    def is_terminated(
        self,
        flow: NetworkFlow
    ) -> bool:

        if flow.protocol != "TCP":
            return False

        if not flow.packets:
            return False

        last_packet = flow.packets[-1]

        # TCP FIN flag = 0x01
        # TCP RST flag = 0x04
        fin_flag = bool(last_packet.tcp_flags & 0x01)
        rst_flag = bool(last_packet.tcp_flags & 0x04)

        return fin_flag or rst_flag

    # -------------------------------------------------------------
    # INACTIVITY DETECTION
    # -------------------------------------------------------------

    def get_expired_flows(
        self,
        current_time: datetime | None = None
    ) -> list[NetworkFlow]:

        if current_time is None:
            current_time = datetime.now()

        timeout = timedelta(
            seconds=self.inactivity_timeout
        )

        expired = []

        for flow in list(self.flows.values()):

            if current_time - flow.last_seen >= timeout:
                expired.append(flow)

        return expired

    # -------------------------------------------------------------
    # REMOVE FLOW
    # -------------------------------------------------------------

    def remove_flow(
        self,
        flow: NetworkFlow
    ):

        key = self.get_flow_key(
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol
        )

        self.flows.pop(key, None)

    # -------------------------------------------------------------
    # ACTIVE FLOWS
    # -------------------------------------------------------------

    def get_active_flows(self):
        return list(self.flows.values())

    # -------------------------------------------------------------
    # CLEAR ALL
    # -------------------------------------------------------------

    def clear(self):
        self.flows.clear()

    # -------------------------------------------------------------
    # LENGTH
    # -------------------------------------------------------------

    def __len__(self):
        return len(self.flows)