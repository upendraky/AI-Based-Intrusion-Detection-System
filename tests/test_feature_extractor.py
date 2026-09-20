import joblib

from src.flow.flow_manager import FlowManager
from src.features.live_feature_extractor import LiveFeatureExtractor


selector = joblib.load(
    "models/feature_selector.pkl"
)

feature_names = selector.feature_names_in_

extractor = LiveFeatureExtractor(
    feature_names
)

manager = FlowManager()

flow = manager.add_packet(
    src_ip="172.20.10.2",
    dst_ip="162.125.40.1",
    src_port=63251,
    dst_port=443,
    protocol="TCP",
    packet_size=104
)

manager.add_packet(
    src_ip="172.20.10.2",
    dst_ip="162.125.40.1",
    src_port=63251,
    dst_port=443,
    protocol="TCP",
    packet_size=200
)

features = extractor.extract(flow)

print("=" * 60)
print("LIVE FEATURE EXTRACTOR TEST")
print("=" * 60)

print("Input feature count:", len(features.columns))
print("Expected feature count:", len(feature_names))
print("Rows:", len(features))

print("\nSelected features after selector:")

selected = selector.transform(features)

print("Selected shape:", selected.shape)

print("\nSample features:")

for column in [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size"
]:
    print(
        f"{column}: "
        f"{features[column].iloc[0]}"
    )

print("=" * 60)

