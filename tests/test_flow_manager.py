from datetime import datetime, timedelta

from src.flow.flow_manager import FlowManager


manager = FlowManager()

start = datetime.now()

flow = manager.add_packet(
    src_ip="172.20.10.2",
    dst_ip="162.125.40.1",
    src_port=63251,
    dst_port=443,
    protocol="TCP",
    packet_size=104,
    timestamp=start
)

manager.add_packet(
    src_ip="172.20.10.2",
    dst_ip="162.125.40.1",
    src_port=63251,
    dst_port=443,
    protocol="TCP",
    packet_size=200,
    timestamp=start + timedelta(seconds=1)
)

manager.add_packet(
    src_ip="162.125.40.1",
    dst_ip="172.20.10.2",
    src_port=443,
    dst_port=63251,
    protocol="TCP",
    packet_size=150,
    timestamp=start + timedelta(seconds=2)
)


print("=" * 60)
print("FLOW MANAGER TEST")
print("=" * 60)

print("Active flows:", len(manager))
print("Total packets:", flow.total_packets)
print("Total bytes:", flow.total_bytes)
print("Forward packets:", flow.forward_packets)
print("Backward packets:", flow.backward_packets)
print("Forward bytes:", flow.forward_bytes)
print("Backward bytes:", flow.backward_bytes)
print("Duration:", flow.duration)
print("Average packet size:", flow.average_packet_size)
print("Packets/sec:", flow.flow_packets_per_second)
print("Bytes/sec:", flow.flow_bytes_per_second)

print("=" * 60)
