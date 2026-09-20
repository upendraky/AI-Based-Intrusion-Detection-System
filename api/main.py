from pathlib import Path
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel

from sqlalchemy import func

from api.database import SessionLocal, Detection


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "models" / "best_ids_model.pkl"

SELECTOR_PATH = BASE_DIR / "models" / "feature_selector.pkl"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Sentinel AI IDS",
    description="AI-Based Intrusion Detection System",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ============================================================
# JINJA2
# ============================================================

templates = Jinja2Templates(
    directory=str(
        BASE_DIR / "api" / "templates"
    )
)


# ============================================================
# LOAD MODEL
# ============================================================

model = None
selector = None


try:

    model = joblib.load(
        MODEL_PATH
    )

    selector = joblib.load(
        SELECTOR_PATH
    )

    print("========================================")
    print("Sentinel AI IDS")
    print("========================================")
    print("XGBoost model loaded successfully.")
    print("Feature selector loaded successfully.")
    print("PostgreSQL persistence enabled.")
    print("========================================")


except Exception as e:

    print("========================================")
    print("MODEL LOADING ERROR")
    print("========================================")
    print(e)
    print("========================================")


# ============================================================
# REQUEST MODEL
# ============================================================

class PredictionRequest(BaseModel):

    features: dict


# ============================================================
# THREAT CALCULATION
# ============================================================

def calculate_threat(probability: float):

    probability = max(
        0.0,
        min(1.0, float(probability))
    )

    threat_score = round(
        probability * 100,
        2
    )

    if threat_score >= 90:
        severity = "CRITICAL"

    elif threat_score >= 70:
        severity = "HIGH"

    elif threat_score >= 40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return threat_score, severity


# ============================================================
# FRONTEND
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
def dashboard(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={}
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health():

    database_status = "offline"

    db = None

    try:

        db = SessionLocal()

        db.execute(
            func.now().select()
        )

        database_status = "online"

    except Exception:

        database_status = "offline"

    finally:

        if db:
            db.close()

    return {

        "status": "online",

        "model_loaded":
            model is not None,

        "selector_loaded":
            selector is not None,

        "database":
            database_status
    }


# ============================================================
# MODEL INFORMATION
# ============================================================

@app.get("/api/model")
def model_info():

    return {

        "status":
            "online"
            if model is not None
            else "offline",

        "model":
            "XGBoost",

        "type":
            "Binary Classification",

        "classes": [
            "BENIGN",
            "DDoS"
        ],

        "feature_selection":
            "SelectKBest",

        "model_file":
            "best_ids_model.pkl",

        "selector_file":
            "feature_selector.pkl"
    }


# ============================================================
# AI PREDICTION
# ============================================================

@app.post("/api/predict")
def predict(
    request: PredictionRequest
):

    if model is None:

        raise HTTPException(
            status_code=503,
            detail="AI model is not loaded."
        )

    if selector is None:

        raise HTTPException(
            status_code=503,
            detail="Feature selector is not loaded."
        )

    try:

        # ====================================================
        # JSON → DATAFRAME
        # ====================================================

        input_df = pd.DataFrame(
            [request.features]
        )


        # ====================================================
        # NUMERIC CONVERSION
        # ====================================================

        input_df = input_df.apply(
            pd.to_numeric,
            errors="coerce"
        )


        # ====================================================
        # INFINITY
        # ====================================================

        input_df = input_df.replace(
            [np.inf, -np.inf],
            np.nan
        )


        # ====================================================
        # VALIDATE
        # ====================================================

        if input_df.isnull().any().any():

            invalid_features = (
                input_df.columns[
                    input_df.isnull().any()
                ].tolist()
            )

            raise HTTPException(

                status_code=400,

                detail={

                    "message":
                        "Invalid feature values.",

                    "features":
                        invalid_features
                }
            )


        # ====================================================
        # FEATURE ORDER
        # ====================================================

        if hasattr(
            selector,
            "feature_names_in_"
        ):

            expected_features = (
                selector.feature_names_in_
            )

            missing_features = [

                feature

                for feature
                in expected_features

                if feature
                not in input_df.columns
            ]

            if missing_features:

                raise HTTPException(

                    status_code=400,

                    detail={

                        "message":
                            "Missing required features.",

                        "missing_features":
                            missing_features
                    }
                )

            input_df = input_df[
                expected_features
            ]


        # ====================================================
        # SELECT FEATURES
        # ====================================================

        selected_features = (
            selector.transform(
                input_df
            )
        )


        # ====================================================
        # XGBOOST
        # ====================================================

        prediction = int(
            model.predict(
                selected_features
            )[0]
        )


        probabilities = (
            model.predict_proba(
                selected_features
            )[0]
        )


        # IMPORTANT:
        # Class 1 = DDoS
        # Therefore probabilities[1] = P(DDoS)

        ddos_probability = float(
            probabilities[1]
        )


        confidence = float(
            np.max(probabilities)
        )


        # ====================================================
        # CLASSIFICATION
        # ====================================================

        label = (
            "DDoS"
            if prediction == 1
            else "BENIGN"
        )


        # Threat score always represents
        # probability of the DDoS class.

        threat_score, severity = (
            calculate_threat(
                ddos_probability
            )
        )


        # ====================================================
        # SAVE TO POSTGRESQL
        # ====================================================

        db = SessionLocal()

        try:

            detection = Detection(

                timestamp=datetime.utcnow(),

                prediction=prediction,

                label=label,

                # Confidence of the predicted class
                confidence=round(
                    confidence * 100,
                    2
                ),

                threat_score=threat_score,

                severity=severity,

                source="CICIDS2017 Simulator",

                status="Detected"
            )


            db.add(detection)

            db.commit()

            db.refresh(detection)

            event_id = detection.id


        except Exception as database_error:

            db.rollback()

            raise HTTPException(

                status_code=500,

                detail={

                    "message":
                        "Prediction succeeded but database save failed.",

                    "error":
                        str(database_error)
                }
            )

        finally:

            db.close()


        # ====================================================
        # RESPONSE
        # ====================================================

        return {

            "prediction":
                prediction,

            "label":
                label,

            "confidence":
                round(
                    confidence * 100,
                    2
                ),

            "ddos_probability":
                round(
                    ddos_probability * 100,
                    4
                ),

            "threat_score":
                threat_score,

            "severity":
                severity,

            "event_id":
                event_id,

            "source":
                "CICIDS2017 Simulator",

            "timestamp":
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        }


    except HTTPException:

        raise


    except Exception as e:

        raise HTTPException(

            status_code=500,

            detail=str(e)
        )


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

@app.get("/api/dashboard/summary")
def dashboard_summary():

    db = SessionLocal()

    try:

        total = db.query(
            func.count(Detection.id)
        ).scalar() or 0


        ddos = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.prediction == 1
        ).scalar() or 0


        benign = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.prediction == 0
        ).scalar() or 0


        live_total = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.source == "Live Network"
        ).scalar() or 0


        live_ddos = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.source == "Live Network",
            Detection.prediction == 1
        ).scalar() or 0


        live_benign = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.source == "Live Network",
            Detection.prediction == 0
        ).scalar() or 0


        simulator_total = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.source == "CICIDS2017 Simulator"
        ).scalar() or 0


        # Runtime threat rate.
        # This is NOT model recall.

        threat_rate = (
            round(
                (ddos / total) * 100,
                2
            )
            if total > 0
            else 0.0
        )


        live_threat_rate = (
            round(
                (live_ddos / live_total) * 100,
                2
            )
            if live_total > 0
            else 0.0
        )


        return {

            "total_traffic":
                total,

            "threats_detected":
                ddos,

            "benign_traffic":
                benign,

            "threat_rate":
                threat_rate,

            "live_total":
                live_total,

            "live_ddos":
                live_ddos,

            "live_benign":
                live_benign,

            "live_threat_rate":
                live_threat_rate,

            "simulator_total":
                simulator_total,

            "model":
                "XGBoost",

            "status":
                "active"
        }


    finally:

        db.close()


# ============================================================
# TRAFFIC HISTORY
# ============================================================

@app.get("/api/traffic")
def traffic():

    db = SessionLocal()

    try:

        rows = (
            db.query(Detection)
            .order_by(
                Detection.id.desc()
            )
            .limit(20)
            .all()
        )

        rows.reverse()

        data = []

        for row in rows:

            data.append({

                "id":
                    row.id,

                "time":
                    row.timestamp.strftime(
                        "%H:%M:%S"
                    ),

                "traffic":
                    int(
                        row.packet_count
                        or 0
                    ),

                "packets":
                    int(
                        row.packet_count
                        or 0
                    ),

                "bytes":
                    int(
                        row.byte_count
                        or 0
                    ),

                "prediction":
                    int(
                        row.prediction
                        or 0
                    ),

                "label":
                    row.label,

                "threat_score":
                    float(
                        row.threat_score
                        or 0
                    ),

                "severity":
                    row.severity,

                "source":
                    row.source

            })

        return {

            "data":
                data

        }

    finally:

        db.close()

# ============================================================
# RECENT THREATS
# ============================================================

@app.get("/api/threats")
def threats():

    db = SessionLocal()

    try:

        rows = db.query(
            Detection
        ).filter(
            Detection.prediction == 1
        ).order_by(
            Detection.id.desc()
        ).limit(
            20
        ).all()


        return {

            "threats": [

                {

                    "id":
                        row.id,

                    "type":
                        row.label,

                    "severity":
                        row.severity,

                    "confidence":
                        row.confidence,

                    "threat_score":
                        row.threat_score,

                    "source":
                        row.source,

                    "status":
                        row.status,

                    "src_ip":
                        row.src_ip,

                    "dst_ip":
                        row.dst_ip,

                    "src_port":
                        row.src_port,

                    "dst_port":
                        row.dst_port,

                    "protocol":
                        row.protocol,

                    "packet_count":
                        row.packet_count,

                    "byte_count":
                        row.byte_count,

                    "timestamp":
                        row.timestamp.strftime(
                            "%H:%M:%S"
                        )
                }

                for row in rows
            ]
        }


    finally:

        db.close()


# ============================================================
# LIVE DETECTIONS
# ============================================================

@app.get("/api/live-detections")
def live_detections():

    db = SessionLocal()

    try:

        rows = db.query(
            Detection
        ).filter(
            Detection.source == "Live Network"
        ).order_by(
            Detection.id.desc()
        ).limit(
            20
        ).all()


        return {

            "detections": [

                {

                    "id":
                        row.id,

                    "timestamp":
                        row.timestamp.strftime(
                            "%H:%M:%S"
                        ),

                    "label":
                        row.label,

                    "severity":
                        row.severity,

                    "confidence":
                        row.confidence,

                    "threat_score":
                        row.threat_score,

                    "src_ip":
                        row.src_ip,

                    "dst_ip":
                        row.dst_ip,

                    "src_port":
                        row.src_port,

                    "dst_port":
                        row.dst_port,

                    "protocol":
                        row.protocol,

                    "packet_count":
                        row.packet_count,

                    "byte_count":
                        row.byte_count,

                    "duration":
                        row.duration,

                    "status":
                        row.status
                }

                for row in rows
            ]
        }


    finally:

        db.close()


# ============================================================
# SOURCE SUMMARY
# ============================================================

@app.get("/api/source-summary")
def source_summary():

    db = SessionLocal()

    try:

        simulator = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.source == "CICIDS2017 Simulator"
        ).scalar() or 0


        live = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.source == "Live Network"
        ).scalar() or 0


        return {

            "simulator":
                simulator,

            "live_network":
                live
        }


    finally:

        db.close()


# ============================================================
# THREAT SCORE
# ============================================================

@app.get("/api/threat-score")
def threat_score():

    db = SessionLocal()

    try:

        # Prefer the most recent LIVE detection.
        # If none exists, fall back to the latest detection.

        latest_live = db.query(
            Detection
        ).filter(
            Detection.source == "Live Network"
        ).order_by(
            Detection.id.desc()
        ).first()


        latest = latest_live

        if latest is None:

            latest = db.query(
                Detection
            ).order_by(
                Detection.id.desc()
            ).first()


        if latest is None:

            return {

                "score":
                    0,

                "level":
                    "LOW",

                "severity":
                    "LOW",

                "model":
                    "XGBoost",

                "source":
                    None
            }


        score = float(
            latest.threat_score
        )


        if score >= 90:
            level = "CRITICAL"

        elif score >= 70:
            level = "HIGH"

        elif score >= 40:
            level = "MEDIUM"

        else:
            level = "LOW"


        return {

            "score":
                score,

            "level":
                level,

            "severity":
                latest.severity,

            "model":
                "XGBoost",

            "source":
                latest.source,

            "timestamp":
                latest.timestamp.strftime(
                    "%H:%M:%S"
                )
        }


    finally:

        db.close()


# ============================================================
# DATABASE STATUS
# ============================================================

@app.get("/api/status")
def detection_status():

    db = SessionLocal()

    try:

        total = db.query(
            func.count(Detection.id)
        ).scalar() or 0


        benign = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.prediction == 0
        ).scalar() or 0


        ddos = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.prediction == 1
        ).scalar() or 0


        live = db.query(
            func.count(Detection.id)
        ).filter(
            Detection.source == "Live Network"
        ).scalar() or 0


        latest = db.query(
            Detection
        ).order_by(
            Detection.id.desc()
        ).first()


        return {

            "total_flows":
                total,

            "benign_flows":
                benign,

            "ddos_flows":
                ddos,

            "live_flows":
                live,

            "latest_label":
                latest.label
                if latest
                else "BENIGN",

            "latest_threat_score":
                latest.threat_score
                if latest
                else 0,

            "latest_severity":
                latest.severity
                if latest
                else "LOW",

            "latest_source":
                latest.source
                if latest
                else None,

            "last_updated":
                latest.timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if latest
                else None
        }


    finally:

        db.close()


# ============================================================
# SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )