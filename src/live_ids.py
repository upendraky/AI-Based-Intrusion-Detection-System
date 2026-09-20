import threading
import time

from scapy.all import sniff
from scapy.layers.inet import IP

from api.database import SessionLocal, Detection

from src.flow.flow_manager import FlowManager
from src.live_predictor import LivePredictor
from src.parsing.packet_parser import PacketParser


# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = "en0"

INACTIVITY_TIMEOUT = 5.0

MIN_PACKETS_FOR_PREDICTION = 5


# ============================================================
# INITIALIZE COMPONENTS
# ============================================================

flow_manager = FlowManager(
    inactivity_timeout=INACTIVITY_TIMEOUT
)

predictor = LivePredictor()


# ============================================================
# CALCULATE THREAT INFORMATION
# ============================================================

def calculate_threat(probability):
    """
    Convert the model's DDoS probability into:

    label
    threat score
    severity
    """

    # Probability returned by the model is:
    # P(DDoS)

    probability = max(
        0.0,
        min(1.0, float(probability))
    )

    threat_score = probability * 100

    if threat_score >= 90:
        severity = "CRITICAL"

    elif threat_score >= 70:
        severity = "HIGH"

    elif threat_score >= 40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    # Classification label is based on the
    # model prediction handled separately.

    return threat_score, severity


# ============================================================
# SAVE DETECTION TO POSTGRESQL
# ============================================================

def save_detection(
    flow,
    prediction,
    probability
):
    """
    Save one completed network-flow detection
    into PostgreSQL.
    """

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    label = (
        "DDoS"
        if prediction == 1
        else "BENIGN"
    )

    # --------------------------------------------------------
    # Threat score
    # --------------------------------------------------------

    threat_score, severity = calculate_threat(
        probability
    )

    # --------------------------------------------------------
    # Create database session
    # --------------------------------------------------------

    db = SessionLocal()

    try:

        detection = Detection(

            prediction=int(prediction),

            label=label,

            confidence=float(probability),

            threat_score=float(threat_score),

            severity=severity,

            source="Live Network",

            status="Detected",

            src_ip=flow.src_ip,

            dst_ip=flow.dst_ip,

            src_port=flow.src_port,

            dst_port=flow.dst_port,

            protocol=flow.protocol,

            packet_count=flow.total_packets,

            byte_count=flow.total_bytes,

            duration=float(flow.duration)
        )

        db.add(detection)

        db.commit()

        db.refresh(detection)

        print(
            f"[DATABASE] Detection saved "
            f"(ID={detection.id})"
        )

    except Exception as error:

        db.rollback()

        print(
            f"[DATABASE ERROR] {error}"
        )

    finally:

        db.close()


# ============================================================
# PREDICT COMPLETED FLOW
# ============================================================

def predict_flow(flow):
    """
    Run the ML model on a completed flow
    and save the result to PostgreSQL.
    """

    # --------------------------------------------------------
    # Ignore very small flows
    # --------------------------------------------------------

    if flow.total_packets < MIN_PACKETS_FOR_PREDICTION:

        print(
            f"[FLOW IGNORED] "
            f"Packets={flow.total_packets} "
            f"Src={flow.src_ip} "
            f"Dst={flow.dst_ip}"
        )

        return

    try:

        # ----------------------------------------------------
        # ML prediction
        # ----------------------------------------------------

        result = predictor.predict_flow(flow)

        prediction = result["prediction"]

        probability = result["probability"]

        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        label = (
            "DDoS"
            if prediction == 1
            else "BENIGN"
        )

        # ----------------------------------------------------
        # Threat score
        # ----------------------------------------------------

        threat_score, severity = calculate_threat(
            probability
        )

        # ----------------------------------------------------
        # Terminal output
        # ----------------------------------------------------

        print()

        print("-" * 60)

        print("FLOW COMPLETED")

        print("-" * 60)

        print(
            f"Source       : "
            f"{flow.src_ip}:{flow.src_port}"
        )

        print(
            f"Destination  : "
            f"{flow.dst_ip}:{flow.dst_port}"
        )

        print(
            f"Protocol     : "
            f"{flow.protocol}"
        )

        print(
            f"Packets      : "
            f"{flow.total_packets}"
        )

        print(
            f"Bytes        : "
            f"{flow.total_bytes}"
        )

        print(
            f"Duration     : "
            f"{flow.duration:.4f} sec"
        )

        print(
            f"Prediction   : "
            f"{label}"
        )

        print(
            f"DDoS Prob.   : "
            f"{probability:.6f}"
        )

        print(
            f"Threat Score : "
            f"{threat_score:.2f}"
        )

        print(
            f"Severity     : "
            f"{severity}"
        )

        print("-" * 60)

        # ----------------------------------------------------
        # Save to PostgreSQL
        # ----------------------------------------------------

        save_detection(
            flow=flow,
            prediction=prediction,
            probability=probability
        )

        print()

    except Exception as error:

        print()

        print("[PREDICTION ERROR]")

        print(error)

        print()


# ============================================================
# EXPIRE INACTIVE FLOWS
# ============================================================

def expire_flows():
    """
    Background thread that checks for flows
    inactive for more than INACTIVITY_TIMEOUT.
    """

    while True:

        try:

            expired_flows = (
                flow_manager.get_expired_flows()
            )

            for flow in expired_flows:

                # Predict exactly once
                predict_flow(flow)

                # Remove finalized flow
                flow_manager.remove_flow(flow)

        except Exception as error:

            print(
                f"[FLOW EXPIRATION ERROR] "
                f"{error}"
            )

        time.sleep(1)


# ============================================================
# PROCESS PACKET
# ============================================================

def process_packet(packet):

    # --------------------------------------------------------
    # Only process IP packets
    # --------------------------------------------------------

    if IP not in packet:
        return

    # --------------------------------------------------------
    # Parse packet
    # --------------------------------------------------------

    parsed = PacketParser.parse(packet)

    if parsed is None:
        return

    # --------------------------------------------------------
    # Add packet to flow
    # --------------------------------------------------------

    flow = flow_manager.add_packet(

        src_ip=parsed.src_ip,

        dst_ip=parsed.dst_ip,

        src_port=parsed.src_port,

        dst_port=parsed.dst_port,

        protocol=parsed.protocol,

        packet_size=parsed.packet_size,

        timestamp=parsed.timestamp,

        tcp_flags=parsed.tcp_flags,

        tcp_header_length=parsed.tcp_header_length,

        tcp_window=parsed.tcp_window,

        tcp_segment_length=parsed.tcp_segment_length
    )

    # --------------------------------------------------------
    # TCP FIN / RST
    # --------------------------------------------------------

    if flow_manager.is_terminated(flow):

        # Predict once
        predict_flow(flow)

        # Remove completed flow
        flow_manager.remove_flow(flow)

        return


# ============================================================
# START FLOW EXPIRATION THREAD
# ============================================================

expiration_thread = threading.Thread(

    target=expire_flows,

    daemon=True
)

expiration_thread.start()


# ============================================================
# START IDS
# ============================================================

print("=" * 60)

print("SENTINEL AI IDS")

print("=" * 60)

print(
    f"Interface          : "
    f"{INTERFACE}"
)

print(
    f"Inactivity timeout : "
    f"{INACTIVITY_TIMEOUT} seconds"
)

print(
    f"Minimum packets    : "
    f"{MIN_PACKETS_FOR_PREDICTION}"
)

print("=" * 60)

print(
    "Capturing live network traffic..."
)

print(
    "PostgreSQL persistence: ENABLED"
)

print(
    "Flow-based prediction: ENABLED"
)

print(
    "Press Ctrl+C to stop."
)

print("=" * 60)


# ============================================================
# START PACKET CAPTURE
# ============================================================

try:

    sniff(

        iface=INTERFACE,

        prn=process_packet,

        store=False
    )

except KeyboardInterrupt:

    print()

    print("=" * 60)

    print("IDS STOPPED")

    print("=" * 60)

    # --------------------------------------------------------
    # Finalize remaining flows
    # --------------------------------------------------------

    remaining_flows = (
        flow_manager.get_active_flows()
    )

    if remaining_flows:

        print(
            f"Finalizing "
            f"{len(remaining_flows)} "
            f"active flow(s)..."
        )

        for flow in remaining_flows:

            predict_flow(flow)

        flow_manager.clear()

    print(
        "Shutdown complete."
    )