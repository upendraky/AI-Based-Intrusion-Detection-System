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
    print(
        "XGBoost model loaded successfully."
    )
    print(
        "Feature selector loaded successfully."
    )
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

    try:

        db = SessionLocal()

        db.execute(
            func.now().select()
        )

        db.close()

        database_status = "online"

    except Exception:

        database_status = "offline"


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

    # --------------------------------------------------------
    # MODEL CHECK
    # --------------------------------------------------------

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
        # VALIDATE FEATURES
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


        confidence = float(
            np.max(probabilities)
        )


        # ====================================================
        # CLASSIFICATION
        # ====================================================

        if prediction == 1:

            label = "DDoS"

            threat_score = round(
                confidence * 100,
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


        else:

            label = "BENIGN"

            threat_score = round(
                (1 - confidence) * 100,
                2
            )

            severity = "LOW"


        # ====================================================
        # SAVE TO POSTGRESQL
        # ====================================================

        db = SessionLocal()

        try:

            detection = Detection(

                timestamp=datetime.utcnow(),

                prediction=prediction,

                label=label,

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

            "threat_score":
                threat_score,

            "severity":
                severity,

            "event_id":
                event_id,

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

@app.get(
    "/api/dashboard/summary"
)
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


        if total > 0:

            threat_rate = round(
                (ddos / total) * 100,
                2
            )

        else:

            threat_rate = 0.0


        return {

            "total_traffic":
                total,

            "threats_detected":
                ddos,

            "benign_traffic":
                benign,

            "detection_rate":
                threat_rate,

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

        rows = db.query(
            Detection
        ).order_by(
            Detection.id.desc()
        ).limit(
            20
        ).all()


        rows.reverse()


        data = [

            {

                "time":
                    row.timestamp.strftime(
                        "%H:%M:%S"
                    ),

                "traffic":
                    row.id

            }

            for row in rows

        ]


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

                    "source":
                        row.source,

                    "status":
                        row.status,

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
# THREAT SCORE
# ============================================================

@app.get("/api/threat-score")
def threat_score():

    db = SessionLocal()


    try:

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
                    "XGBoost"

            }


        score = latest.threat_score


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
                "XGBoost"

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