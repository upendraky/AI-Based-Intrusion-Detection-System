import numpy as np
import pandas as pd

from src.flow.flow_manager import NetworkFlow


class LiveFeatureExtractor:

    def __init__(self, feature_names):
        self.feature_names = list(feature_names)

    @staticmethod
    def _stats(values):
        if not values:
            return 0.0, 0.0, 0.0, 0.0

        values = np.asarray(values, dtype=float)

        return (
            float(np.min(values)),
            float(np.max(values)),
            float(np.mean(values)),
            float(np.std(values)),
        )

    @staticmethod
    def _iat_stats(iats):
        if not iats:
            return 0.0, 0.0, 0.0, 0.0

        values = np.asarray(iats, dtype=float)

        return (
            float(np.sum(values)),
            float(np.mean(values)),
            float(np.std(values)),
            float(np.max(values)),
        )

    def extract(self, flow: NetworkFlow) -> pd.DataFrame:

        fwd_sizes = flow.forward_sizes
        bwd_sizes = flow.backward_sizes
        all_sizes = flow.all_sizes

        if not fwd_sizes:
            fwd_sizes = [0]

        if not bwd_sizes:
            bwd_sizes = [0]

        if not all_sizes:
            all_sizes = [0]

        (
            fwd_min,
            fwd_max,
            fwd_mean,
            fwd_std
        ) = self._stats(fwd_sizes)

        (
            bwd_min,
            bwd_max,
            bwd_mean,
            bwd_std
        ) = self._stats(bwd_sizes)

        (
            packet_min,
            packet_max,
            packet_mean,
            packet_std
        ) = self._stats(all_sizes)

        (
            bwd_iat_total,
            bwd_iat_mean,
            bwd_iat_std,
            bwd_iat_max
        ) = self._iat_stats(flow.backward_iats)

        duration = max(flow.duration, 1e-6)

        down_up_ratio = (
            flow.backward_packets / flow.forward_packets
            if flow.forward_packets > 0
            else 0.0
        )

        features = {

            # Selected model features
            "Destination Port": flow.dst_port,

            "Total Length of Fwd Packets":
                flow.forward_bytes,

            "Fwd Packet Length Max":
                fwd_max,

            "Fwd Packet Length Min":
                fwd_min,

            "Fwd Packet Length Mean":
                fwd_mean,

            "Fwd Packet Length Std":
                fwd_std,

            "Bwd Packet Length Max":
                bwd_max,

            "Bwd Packet Length Min":
                bwd_min,

            "Bwd Packet Length Mean":
                bwd_mean,

            "Bwd Packet Length Std":
                bwd_std,

            "Flow Packets/s":
                flow.flow_packets_per_second,

            "Bwd IAT Total":
                bwd_iat_total,

            "Bwd IAT Mean":
                bwd_iat_mean,

            "Bwd IAT Std":
                bwd_iat_std,

            "Bwd IAT Max":
                bwd_iat_max,

            "Fwd PSH Flags":
                flow.forward_psh_count,

            "Min Packet Length":
                packet_min,

            "Max Packet Length":
                packet_max,

            "Packet Length Mean":
                packet_mean,

            "Packet Length Std":
                packet_std,

            "Packet Length Variance":
                float(packet_std ** 2),

            "SYN Flag Count":
                flow.syn_count,

            "PSH Flag Count":
                flow.psh_count,

            "URG Flag Count":
                flow.urg_count,

            "Down/Up Ratio":
                down_up_ratio,

            "Average Packet Size":
                flow.average_packet_size,

            "Avg Fwd Segment Size":
                fwd_mean,

            "Avg Bwd Segment Size":
                bwd_mean,

            "Subflow Fwd Bytes":
                flow.forward_bytes,

            "min_seg_size_forward":
                flow.min_forward_segment_size,

            # Additional features required by selector
            "Flow Duration":
                flow.duration * 1_000_000,

            "Total Fwd Packets":
                flow.forward_packets,

            "Total Backward Packets":
                flow.backward_packets,

            "Total Length of Bwd Packets":
                flow.backward_bytes,

            "Flow Bytes/s":
                flow.flow_bytes_per_second,

            "Flow IAT Mean":
                0.0,

            "Flow IAT Std":
                0.0,

            "Flow IAT Max":
                0.0,

            "Flow IAT Min":
                0.0,

            "Fwd IAT Total":
                0.0,

            "Fwd IAT Mean":
                0.0,

            "Fwd IAT Std":
                0.0,

            "Fwd IAT Max":
                0.0,

            "Fwd IAT Min":
                0.0,

            "Fwd Header Length":
                0.0,

            "Bwd Header Length":
                0.0,

            "Fwd Header Length.1":
                0.0,

            "Fwd Packets/s":
                flow.forward_packets / duration,

            "Bwd Packets/s":
                flow.backward_packets / duration,

            "FIN Flag Count":
                0,

            "RST Flag Count":
                0,

            "ACK Flag Count":
                0,

            "ECE Flag Count":
                0,

            "Down/Up Ratio":
                down_up_ratio,

            "Init_Win_bytes_forward":
                0,

            "Init_Win_bytes_backward":
                0,

            "act_data_pkt_fwd":
                flow.forward_packets,

            "Active Mean":
                0.0,

            "Active Std":
                0.0,

            "Active Max":
                0.0,

            "Active Min":
                0.0,

            "Idle Mean":
                0.0,

            "Idle Std":
                0.0,

            "Idle Max":
                0.0,

            "Idle Min":
                0.0,
        }

        # Make absolutely sure the DataFrame has
        # exactly the same columns and order as training.
        for feature in self.feature_names:
            if feature not in features:
                features[feature] = 0.0

        df = pd.DataFrame(
            [features],
            columns=self.feature_names
        )

        df = df.replace(
            [np.inf, -np.inf],
            0
        )

        df = df.fillna(0)

        return df