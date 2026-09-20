from datetime import datetime, timedelta

from src.flow.flow_manager import FlowManager


def main():

    print("=" * 60)
    print("FLOW LIFECYCLE TEST")
    print("=" * 60)

    manager = FlowManager(inactivity_timeout=5)

    start = datetime.now()

    # ---------------------------------------------------------
    # Create a TCP flow
    # ---------------------------------------------------------

    flow = manager.add_packet(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_size=100,
        timestamp=start,
        tcp_flags=0x02,  # SYN
        tcp_segment_length=0
    )

    print(f"Active flows after packet 1: {len(manager)}")

    # ---------------------------------------------------------
    # Add another packet
    # ---------------------------------------------------------

    manager.add_packet(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_size=200,
        timestamp=start + timedelta(seconds=1),
        tcp_flags=0x18,  # PSH + ACK
        tcp_segment_length=160
    )

    print(f"Packets in flow: {flow.total_packets}")

    # ---------------------------------------------------------
    # Check inactivity
    # ---------------------------------------------------------

    expired = manager.get_expired_flows(
        current_time=start + timedelta(seconds=7)
    )

    print(f"Expired flows: {len(expired)}")

    assert len(expired) == 1
    assert expired[0] is flow

    # ---------------------------------------------------------
    # Remove flow
    # ---------------------------------------------------------

    manager.remove_flow(flow)

    print(f"Active flows after removal: {len(manager)}")

    assert len(manager) == 0

    print()
    print("INACTIVITY TEST: PASS")

    # ---------------------------------------------------------
    # Test FIN termination
    # ---------------------------------------------------------

    flow = manager.add_packet(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=50001,
        dst_port=443,
        protocol="TCP",
        packet_size=100,
        timestamp=start,
        tcp_flags=0x02
    )

    manager.add_packet(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=50001,
        dst_port=443,
        protocol="TCP",
        packet_size=100,
        timestamp=start + timedelta(seconds=1),
        tcp_flags=0x11,  # FIN + ACK
    )

    assert manager.is_terminated(flow)

    print("TCP FIN TEST: PASS")

    # ---------------------------------------------------------
    # Test RST termination
    # ---------------------------------------------------------

    flow = manager.add_packet(
        src_ip="192.168.1.30",
        dst_ip="192.168.1.40",
        src_port=50002,
        dst_port=443,
        protocol="TCP",
        packet_size=100,
        timestamp=start,
        tcp_flags=0x02
    )

    manager.add_packet(
        src_ip="192.168.1.30",
        dst_ip="192.168.1.40",
        src_port=50002,
        dst_port=443,
        protocol="TCP",
        packet_size=100,
        timestamp=start + timedelta(seconds=1),
        tcp_flags=0x04,  # RST
    )

    assert manager.is_terminated(flow)

    print("TCP RST TEST: PASS")

    print("=" * 60)
    print("ALL FLOW LIFECYCLE TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
